<?php declare(strict_types=1);

namespace Sunkan\AwsAuthPolicy\ValueObject;

class Arn implements \Stringable
{
    public static function fromString(string $arn): self
    {
        if (!str_starts_with($arn, 'arn:')) {
            throw new \InvalidArgumentException('Arn need to have the following format "arn:%s:%s:%s:%d:%s/%s/%s/%s"');
        }

        [,$partition, $service, $region, $accountId, $resource] = explode(':', $arn, 6);
        $arnClass = match ($service) {
            's3' => S3Arn::class,
            'execute-api' => ExecuteApiArn::class,
            'lambda' => LambdaArn::class,
            'iam', 'sts' => IamArn::class,
            default => self::class,
        };

        return new $arnClass(
            $partition,
            $service,
            $region,
            $accountId,
            $resource,
        );
    }

    public final function __construct(
        public string $partition,
        public string $service,
        public string|null $region,
        public string|null $accountId,
        public string $resource,
    ) {
        $this->parseResource($this->resource);
    }

    protected function parseResource(string $resource): void {}

    public function toString(): string
    {
        return sprintf(
            'arn:%s:%s:%s:%s:%s',
            $this->partition,
            $this->service,
            $this->region ?? '',
            $this->accountId ?? '',
            $this->resource,
        );
    }

    public function __toString(): string
    {
        return $this->toString();
    }
}
