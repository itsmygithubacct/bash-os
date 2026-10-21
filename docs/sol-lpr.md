# sol-lpr

`lpr list` reads the private spool with `readdir`. A read error is not the end of the directory. The command reports the error, closes the directory, and returns failure. A missing spool is still an empty successful list.

Cancel still asks the submitter through the job's control FIFO. It does not signal a pid read from a sidecar file. Submit still delivers only to an absolute `BASHLPR_BACKEND` with a literal argv, into an owner-only spool opened with `O_NOFOLLOW`. These checks use a temporary spool and a fake backend. Nothing is sent to a printer, and no timing sample is recorded here.
