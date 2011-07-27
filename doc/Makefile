## Makefile for LaTeX presentations.
## 
## Will compile the LaTeX file as many times as necessary.
## if FAST=1, always compile once
##
## The postscript :
##    make mypres.ps
## The PDF, compile only once, even if the TOC or references are outdated
##    make mypres.pdf FAST=1
## The PDF, 4 slides per page, A4
##    make mypres.a4.4.pdf
## The web page (create a directory, needs album: apt-get install album)
##    make mypres.www
##
## <phil(at)secdev.org>

PSNUPOPTS=-W128mm -H96mm -pa4 -m0.5cm -b0.2cm -d
FORMAT ?= 1

XFIG_FIGS=$(patsubst %.fig,%.eps,$(wildcard fig/*.fig))
DIA_FIGS=$(patsubst %.dia,%.eps,$(wildcard fig/*.dia))
ALL_FIGS=$(XFIG_FIGS) $(DIA_FIGS)

all:
	@echo 'USAGE: make <filename.ext> [FAST=1]'
	@echo 'possible extentions :'
	@echo ' .dvi, .ps or .pdf'
	@echo ' .www to create a directory with web pages'
	@echo ' .a4.n.pdf with n in 1-4,6,8,9,16,32 for n slides per page'


.SUFFIXES: .pdf .tex .ps .dvi .www .eps .fig

# cancel built-in implicit rule tex -> dvi
%.dvi:%.tex

%.eps: %.fig
	fig2dev -L eps $< $@

%.eps: %.dia
	dia -e $@ $<

%.pdf: %.ps
	ps2pdf $*.ps

%.ps: %.dvi
	dvips -Ppdf $*

%.dvi: %.tex $(ALL_FIGS)
	[ -e $*.aux ] || touch $*.aux 
	while true; do                           \
		cp $*.aux $*.aux2               ;\
		echo $(FORMAT) | latex $* || { rm $*.aux2 ; break; }; \
		cmp $*.aux $*.aux2 && break     ;\
		[ -z "$(FAST)" ] || break       ;\
	done
	@# if .aux2 does not exist, there was an error. Next line will be false.
	@[ -e $*.aux2 ] && rm $*.aux2
	@echo "#######[ warnings ]#######"
	@grep -i warning $*.log
	@echo "##########################"


%.a4.0.ps: %.dvi
	dvips -Ppdf -ta4 $* -o $@

%.a4.1.ps: %.a4.0.ps
	psnup $(PSNUPOPTS) -1  $< $@

%.a4.2.ps: %.a4.0.ps
	psnup $(PSNUPOPTS) -2  $< $@

%.a4.3.ps: %.a4.0.ps
	psnup $(PSNUPOPTS) -3  $< $@

%.a4.4.ps: %.a4.0.ps
	psnup $(PSNUPOPTS) -4  $< $@

%.a4.6.ps: %.a4.0.ps
	psnup $(PSNUPOPTS) -6  $< $@

%.a4.8.ps: %.a4.0.ps
	psnup $(PSNUPOPTS) -8  $< $@

%.a4.9.ps: %.a4.0.ps
	psnup $(PSNUPOPTS) -9  $< $@

%.a4.16.ps: %.a4.0.ps
	psnup $(PSNUPOPTS) -16  $< $@

%.a4.24.ps: %.a4.0.ps
	psnup $(PSNUPOPTS) -24  $< $@

%.a4.32.ps: %.a4.0.ps
	psnup $(PSNUPOPTS) -32  $< $@

%.a4.ps: %.a4.0.ps
	mv $< $@

%.jpg: %.ppm
	convert $< $@

# gs or pdftoppm ? pdftoppm : better fonts, graphics not anti-aliased
#gs -dBATCH -dNOPAUSE -dTextAlphaBits=4 -dGraphicsAlphaBits=4 -sDEVICE=png16m -sOutputFile=$@/$@-%04d.png -r150  $<
%.www: %.pdf
	[ -e $@ ] && rm -rf $@ || true
	mkdir $@
	pdftoppm $< $@/$@
	$(MAKE) alljpg PPMDIR=$@
	rm $@/*.ppm
	cd $@ ; album -geometry 200x150

alljpg: 
	@$(MAKE) $(patsubst %.ppm,%.jpg, $(wildcard $(PPMDIR)/*.ppm))


.PRECIOUS: %.dvi %.ps %.pdf %.eps

.PHONY: clean,test

clean:
	rm -f *.toc *.aux *.vrb *.snm *.log *.out *.nav *.ps *.dvi


overclean: clean
	rm -f *.pdf
