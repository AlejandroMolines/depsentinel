// Package workpool ejecuta tareas en paralelo con un límite de concurrencia.
package workpool

import (
	"context"
	"sync"
)

// ForEach llama a fn para cada índice 0..n-1 usando como máximo `workers` goroutines.
// Si el contexto se cancela, las tareas pendientes se omiten.
func ForEach(ctx context.Context, workers, n int, fn func(ctx context.Context, i int)) {
	if n <= 0 {
		return
	}
	if workers < 1 {
		workers = 1
	}
	if workers > n {
		workers = n
	}
	var wg sync.WaitGroup
	idx := make(chan int)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range idx {
				if ctx.Err() != nil {
					continue
				}
				fn(ctx, i)
			}
		}()
	}
	for i := 0; i < n; i++ {
		idx <- i
	}
	close(idx)
	wg.Wait()
}
