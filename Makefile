include $(GOROOT)/src/Make.inc

TARG = xar
GOFILES =\
	xar.go\
	readtoc.go

include $(GOROOT)/src/Make.pkg
