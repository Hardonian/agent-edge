package apcap

import "errors"

var (
	// ErrInvalidCapture indicates a malformed or unrecognizable APCAP archive.
	ErrInvalidCapture = errors.New("invalid apcap capture archive")

	// ErrUnsupportedVersion indicates the capture was created with an incompatible format version.
	ErrUnsupportedVersion = errors.New("unsupported apcap format version")

	// ErrCorruptBundle indicates checksum mismatch or truncated archive contents.
	ErrCorruptBundle = errors.New("corrupt apcap bundle or hash mismatch")

	// ErrPathTraversal indicates a potentially malicious relative path in the archive (Zip-slip).
	ErrPathTraversal = errors.New("illegal path traversal detected in archive entry")

	// ErrDecompressionBomb indicates the archive expanded beyond safety limits.
	ErrDecompressionBomb = errors.New("decompression bomb safety threshold exceeded")

	// ErrCaptureLimit indicates max event or size bounds were exceeded.
	ErrCaptureLimit = errors.New("capture limits exceeded")
)
