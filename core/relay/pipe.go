package relay

import "io"

// Pipe copies bytes in both directions between a and b until either side ends,
// then closes both. It returns the total bytes a→b and b→a.
func Pipe(a, b io.ReadWriteCloser) (ab, ba int64) {
	type res struct {
		n   int64
		dir int // 0 = a->b, 1 = b->a
	}
	done := make(chan res, 2)
	go func() {
		n, _ := io.Copy(b, a)
		done <- res{n, 0}
	}()
	go func() {
		n, _ := io.Copy(a, b)
		done <- res{n, 1}
	}()

	first := <-done
	// Closing both unblocks the other copy.
	a.Close()
	b.Close()
	second := <-done

	for _, r := range []res{first, second} {
		if r.dir == 0 {
			ab = r.n
		} else {
			ba = r.n
		}
	}
	return ab, ba
}
