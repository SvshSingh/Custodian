FROM python:3.12-slim

# Bytecode writing off and unbuffered output: standard for containers, where
# the filesystem is ephemeral and logs need to appear immediately.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# One install layer. The package is built from source by hatchling, so app/
# has to be present before pip runs and a code change does rebuild the
# dependency install. Splitting them would mean maintaining a second copy of
# the dependency list purely for layer caching, which is a worse trade at
# this size.
COPY pyproject.toml README.md ./
COPY app ./app
RUN pip install --no-cache-dir .

# Run as a non-root user. This service writes private keys; if it is ever
# compromised, the blast radius should not include the whole container.
RUN useradd --create-home --uid 1000 certward \
    && mkdir -p /app/data \
    && chown -R certward:certward /app
USER certward

EXPOSE 8000

# No --reload here: it is a development convenience that watches the
# filesystem and doubles the process count.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
