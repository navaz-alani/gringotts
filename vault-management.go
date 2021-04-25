package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

// MAX_TESTS specifies the maximum number of ciphertext integrity tests that can
// be run in parallel.
// It exists to prevent overloading the operating system and consuming too any
// file descriptors, which may result in many inconclusive tests.
const MAX_TESTS = 50

// Cleanup removes all ciphertext files in the vault directory which do not
// correspond to entries in the vault.
// Errors encountered while deleting the ciphertext files are ignored.
func (v *AESVault) Cleanup() ([]string, error) {
	dirContents, err := ioutil.ReadDir(v.dirName)
	if err != nil {
		return nil, fmt.Errorf("failed to get vault contents: %s", err.Error())
	}
	// collect all ciphertexts in the vault directory
	var ciphertexts map[string]bool
	for _, f := range dirContents {
		if !f.IsDir() && f.Name() != vaultFile {
			// consider all files in vault directory as ciphertext (except vaultFile);
			// initially, mark them as "not corresponding to an entry";
			ciphertexts[v.dirName+"/"+f.Name()] = false
		}
	}
	// check off the entries which correspond to entries
	for _, entry := range v.Files {
		ciphertexts[entry.EncryptedName] = true
	}
	// collect the unlinked ciphertexts and delete them
	var unlinkedCiphertexts []string
	for k, v := range ciphertexts {
		if v {
			unlinkedCiphertexts = append(unlinkedCiphertexts, k)
			os.Remove(k)
		}
	}
	return unlinkedCiphertexts, nil
}

// PruneEntries removes all entries in the vault whose corresponding ciphertext
// file does not exist.
// If, for some entry, it cannot be determined (with 100% certainty) that a
// corresponding ciphertext file does not exist, then the entry is not deleted.
func (v *AESVault) PruneEntries() ([]string, error) {
	// collect indices of entries whose corresponding ciphertext doesn't exist
	var invalidIdxs []int
	for idx, entry := range v.Files {
		if _, err := os.Stat(entry.EncryptedName); os.IsNotExist(err) {
			// file does not exist - mark entry for removal
			invalidIdxs = append(invalidIdxs, idx)
		}
	}
	// prune the entries, collecting the original filenames
	var prunedFilenames []string
	// go through invalid indices from largest to smallest!
	for i := len(invalidIdxs) - 1; i >= 0; i++ {
		prunedFilenames = append(prunedFilenames, v.Files[i].Filename)
		// remove entry from vault
		v.Files[i] = v.Files[len(v.Files)-1]
		v.Files = v.Files[:len(v.Files)-1]
	}
	return prunedFilenames, nil
}

// IntegrityTestResult summarizes the result of an IntegrityTest on the
// ciphertexts corresponding to file entries in the vault.
// Each field contains the (original) names of the files which fall in that test
// result category.
type IntegrityTestResult struct {
	Failed       []string
	Passed       []string
	Inconclusive []string
}

// integrityTestReporter is a struct passed to every concurrent instance of a
// ciphertext integrity test to report the result of the test.
type integrityTestReporter struct {
	failed       chan<- string
	passed       chan<- string
	inconclusive chan<- string
}

// IntegrityTest tests the integrity of the ciphertext files corresponding to
// the entries in the vault.
// It returns a struct with the test results for the file entries, in 3
// categories.
// These are "failed" (ciphertext file seems to be malformed/tampered with),
// "passed" (ciphertext file is ok) or "inconclusive" (test could not be
// completed).
// A test could be inconclusive if, for example the ciphertext file
// corresponding to the entry is not present, or there are errors while
// computing the HMAC tag/reading from the ciphertext file.
//
// It runs at most MAX_TESTS tests concurrently to avoid using too many
// operating system file descriptors.
func (v *AESVault) IntegrityTest() IntegrityTestResult {
	var result IntegrityTestResult
	// set up test reporting channels
	failed := make(chan string)
	passed := make(chan string)
	inconclusive := make(chan string)
	// set up test reporter
	reporter := integrityTestReporter{
		failed:       failed,
		passed:       passed,
		inconclusive: inconclusive,
	}
	// test runner state
	var currIdx int
	var completedTests int
	var runningTests int
	// run tests concurrently
	for {
		select {
		case file := <-failed:
			{
				result.Failed = append(result.Failed, file)
				completedTests++
				runningTests--
			}
		case file := <-passed:
			{
				result.Passed = append(result.Passed, file)
				completedTests++
				runningTests--
			}
		case file := <-inconclusive:
			{
				result.Inconclusive = append(result.Inconclusive, file)
				completedTests++
				runningTests--
			}
		default:
			{
				if runningTests == 0 && completedTests == len(v.Files) {
					return result // done running tests
				}
				// dispatch one more test if possible
				if runningTests < MAX_TESTS && currIdx < len(v.Files) {
					go v.entryIntegrityParallel(&reporter, currIdx)
					currIdx++
					runningTests++
				}
			}
		}
	}
}

func (v *AESVault) entryIntegrityParallel(reporter *integrityTestReporter, idx int) {
	filename := v.Files[idx].Filename
	pass, err := v.entryIntegrity(idx) // run test
	// report results
	if err != nil {
		reporter.inconclusive <- filename
	} else if pass {
		reporter.passed <- filename
	} else {
		reporter.failed <- filename
	}
}

// entryIntegrity checks the integrity of the ciphertext corresponding to the
// VaultEntry at index idx.
// It returns true if the test passes.
// If false is returned and the error is nil, then the test has failed.
// Otherwise, if the error is non-nil, then the test failed to complete and the
// result is inconclusive.
func (v *AESVault) entryIntegrity(idx int) (bool, error) {
	// open ciphertext file corresponding to file entry at idx
	f, err := os.Open(v.Files[idx].EncryptedName)
	if err != nil {
		return false, fmt.Errorf("error opening ciphertext file: %s", err.Error())
	}
	// get ciphertext file info
	info, err := f.Stat()
	if err != nil {
		return false, fmt.Errorf("error obtaining file info: %s", err)
	}
	// file size must be a multiple of AES_BS (AES cipher block size)
	if info.Size()%AES_BS != 0 {
		return false, nil
	}
	// compute sum and ensure it is the same as in the entry
	buff := make([]byte, AES_BS)
	mac := hmac.New(sha256.New, v.key)
	numBlocks := info.Size() / AES_BS
	for i := int64(0); i < numBlocks; i++ {
		if _, err := io.ReadFull(f, buff); err != nil {
			return false, fmt.Errorf("unexpected EOF while computing HMAC: %s", err.Error())
		}
		if _, err := mac.Write(buff); err != nil {
			return false, fmt.Errorf("hmac compute error: %s", err.Error())
		}
	}
	// compare HMACs and return result
	return hmac.Equal(mac.Sum(nil), v.Files[idx].HMAC), nil
}
