package inventory

import (
	"log"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/unix"
)

type FileEvent struct {
	Path      string
	EventMask uint32 // unix.IN_* flags
}

type FileInventory struct {
	fd       int
	watches  map[int]string // inotify watch descriptor -> path
	eventsCh chan FileEvent
}

func NewFileInventory() (*FileInventory, error) {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return nil, err
	}
	return &FileInventory{
		fd:       fd,
		watches:  make(map[int]string),
		eventsCh: make(chan FileEvent, 512),
	}, nil
}

// Watch adds an inotify watch on a path for create/modify/delete events.
func (fi *FileInventory) Watch(path string) error {
	wd, err := unix.InotifyAddWatch(fi.fd, path,
		unix.IN_CREATE|unix.IN_MODIFY|unix.IN_DELETE|unix.IN_MOVED_FROM|unix.IN_MOVED_TO|unix.IN_CLOSE_WRITE)
	if err != nil {
		return err
	}
	fi.watches[wd] = path
	log.Printf("[FileInventory] Watching: %s", path)
	return nil
}

// Events returns the channel through which FileEvents are emitted.
func (fi *FileInventory) Events() <-chan FileEvent {
	return fi.eventsCh
}

// Run blocks and continuously reads inotify events, sending them to the channel.
func (fi *FileInventory) Run() {
	buf := make([]byte, 4096)
	for {
		n, err := unix.Read(fi.fd, buf)
		if err != nil || n == 0 {
			return
		}
		var offset uint32
		for offset+unix.SizeofInotifyEvent <= uint32(n) {
			raw := (*unix.InotifyEvent)(unsafe.Pointer(&buf[offset]))
			wd := int(raw.Wd)
			mask := raw.Mask

			name := ""
			if raw.Len > 0 {
				nameBytes := buf[offset+unix.SizeofInotifyEvent : offset+unix.SizeofInotifyEvent+raw.Len]
				name = nullTerminated(nameBytes)
			}

			basePath := fi.watches[wd]
			fullPath := filepath.Join(basePath, name)

			select {
			case fi.eventsCh <- FileEvent{Path: fullPath, EventMask: mask}:
			default:
			}

			offset += unix.SizeofInotifyEvent + raw.Len
		}
	}
}

func (fi *FileInventory) Close() {
	unix.Close(fi.fd)
}

func nullTerminated(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
