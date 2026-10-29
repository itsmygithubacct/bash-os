# Top interactive terminal evidence

Both core builds show bounded redraw samples and visible frames at the requested delay. The valid and invalid delay prompts pass. Both sort keys reach the prompt check and fail to display it; subsequent sort values and responses are unreached. Timeout cleanup is not an independent terminal-restoration failure.

FIFO sample counting is source-bound and cannot independently observe invisible redraws without a sample or changed bytes. Existing evidence for scrolling, resize, recovery, exits and restoration remains. Migration describes evidence coverage and retains failures.
