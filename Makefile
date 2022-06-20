.PHONY: clean
clean:
	-rm -rf .venv
	-rm -rf .pytest_cache
	find . | grep -E "(/__pycache__$$|\.pyc$$|\.pyo$$)" | xargs rm -rf

.PHONY: init
init:
	bash -c "asdf plugin add $$(asdf plugin list all | grep 'python ')"; \
	bash -c "asdf plugin add $$(asdf plugin list all | grep 'poetry ')"; \
	bash -c "SDKROOT=/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX12.3.sdk MACOSX_DEPLOYMENT_TARGET=12.3 asdf install"; \
	poetry install; \
	poetry run pre-commit install

.PHONY: test
test: .venv
	poetry run pytest tests

.venv:
	poetry install
