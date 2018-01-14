PM := $(shell find lib -name '*.pm6')

HTML := $(addsuffix .html, $(subst lib,html,$(PM)))

check: html test
	git diff-index --check HEAD

test:
	prove6

html/%.html: lib/%
	mkdir -p $(dir $@)
	perl6 --doc=HTML $< > $@

html: $(HTML)
