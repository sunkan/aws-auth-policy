<?php declare(strict_types=1);

namespace Sunkan\AwsAuthPolicy\ValueObject;

final class S3Arn extends Arn
{
    public string $bucket = '';
    public string $path = '';

    protected function parseResource(string $resource): void
    {
        [$this->bucket, $this->path] = explode('/', $resource, 2);
    }
}
