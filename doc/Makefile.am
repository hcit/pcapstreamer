# makefile to dist manpage

man_MANS = pcapstreamer.8

pcapstreamer.8: pcapstreamer.8.xml
	xmlto man pcapstreamer.8.xml

clean-local:
	rm -fr pcapstreamer.8
