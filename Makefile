.PHONY: test test-formal test-e2e install clean

install:
	pip install -e ".[test,server]"

test:
	python -m pytest tests/ -v

test-formal:
	python -m pytest tests/ -v -k "prop_"

test-e2e:
	python -m pytest tests/ -v -k "pipeline"

clean:
	find . -name __pycache__ -exec rm -rf {} +
	find . -name .pytest_cache -exec rm -rf {} +
