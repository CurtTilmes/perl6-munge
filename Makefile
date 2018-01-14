PM := $(shell find lib -name '*.pm6')

HTML := $(addsuffix .html, $(subst lib,html,$(PM)))

check: html
	git diff-index --check HEAD
	prove6

html/%.html: lib/%
	mkdir -p $(dir $@)
	perl6 --doc=HTML $< > $@

html: $(HTML)
