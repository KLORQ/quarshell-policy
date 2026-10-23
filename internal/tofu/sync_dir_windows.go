//go:build windows

package tofu

// Windows rename is durable through the volume's file metadata journal;
// syncing a directory handle is not supported by os.File.Sync.
func syncDirectory(string) error { return nil }
