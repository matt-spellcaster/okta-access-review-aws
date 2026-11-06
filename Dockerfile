# One image for every Lambda; each function picks its handler with image_config.command.
# The base image is pinned by digest. Bump it deliberately (see docs/aws.md).
FROM public.ecr.aws/lambda/python:3.15-arm64@sha256:505a1d4216c7e32169b0b801ebcb6c9e75c4e89bd25b09eb24a1a7ffbac7f3cf

# requirements.txt is produced by scripts/build_image.sh from uv.lock, with hashes.
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --require-hashes --only-binary=:all: \
        --target "${LAMBDA_TASK_ROOT}" -r /tmp/requirements.txt \
    && rm /tmp/requirements.txt

COPY src/access_review "${LAMBDA_TASK_ROOT}/access_review"

CMD ["access_review.aws.handlers.collect"]
