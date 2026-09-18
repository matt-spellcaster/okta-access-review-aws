# One image for every Lambda; each function picks its handler with image_config.command.
# The base image is pinned by digest. Bump it deliberately (see docs/aws.md).
FROM public.ecr.aws/lambda/python:3.14-arm64@sha256:84344aec27870adf6559bd984c5a5dbbc5112fd1b993457cd834f518e387bbd8

# requirements.txt is produced by scripts/build_image.sh from uv.lock, with hashes.
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --require-hashes --only-binary=:all: \
        --target "${LAMBDA_TASK_ROOT}" -r /tmp/requirements.txt \
    && rm /tmp/requirements.txt

COPY src/access_review "${LAMBDA_TASK_ROOT}/access_review"

CMD ["access_review.aws.handlers.collect"]
