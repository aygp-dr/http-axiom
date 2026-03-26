RUBY := /opt/homebrew/opt/ruby/bin/ruby
GEM_BIN := /opt/homebrew/lib/ruby/gems/3.4.0/bin
export PATH := $(GEM_BIN):/opt/homebrew/opt/ruby/bin:$(PATH)

PORT ?= 3033
HAX  ?= ../../hax

.PHONY: setup server db seed audit clean

setup: db seed

db:
	bin/rails db:create db:migrate

seed:
	bin/rails db:seed

server:
	bin/rails server -p $(PORT)

audit: server-bg
	sleep 2
	$(HAX) audit http://localhost:$(PORT) --json || true
	$(HAX) audit http://localhost:$(PORT)/pets --json || true
	$(HAX) audit http://localhost:$(PORT)/pets/1 --json || true
	$(MAKE) server-stop

server-bg:
	bin/rails server -p $(PORT) -d

server-stop:
	-kill $$(lsof -ti tcp:$(PORT)) 2>/dev/null

clean:
	rm -f storage/*.sqlite3
