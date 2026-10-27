package fleet

import (
	"reflect"
	"testing"
)

func TestRemovableMounts(t *testing.T) {
	mounts := "/dev/sda1 / ext4 rw 0 0\n" +
		"/dev/sdb1 /media/jo/USB\\040STICK vfat rw 0 0\n" +
		"/dev/sdc1 /run/media/jo/CARD exfat rw 0 0\n" +
		"//nas/share /media/nas cifs rw 0 0\n" +
		"tmpfs /run/user/1000 tmpfs rw 0 0\n"
	got := removableMountsFrom(mounts)
	if want := []string{"/media/jo/USB STICK", "/run/media/jo/CARD"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	w := &removableWatch{}
	if fresh := w.newRemovable([]string{"/media/a"}); len(fresh) != 0 {
		t.Fatal("media present at start must not be scanned")
	}
	if fresh := w.newRemovable([]string{"/media/a", "/media/b"}); !reflect.DeepEqual(fresh, []string{"/media/b"}) {
		t.Fatalf("fresh: %v", fresh)
	}
	w.newRemovable([]string{"/media/a"})
	if fresh := w.newRemovable([]string{"/media/a", "/media/b"}); !reflect.DeepEqual(fresh, []string{"/media/b"}) {
		t.Fatal("re-inserted media is scanned again")
	}
}
