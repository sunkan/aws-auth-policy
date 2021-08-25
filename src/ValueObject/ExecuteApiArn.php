<?php declare(strict_types=1);

namespace Sunkan\AwsAuthPolicy\ValueObject;

final class ExecuteApiArn extends Arn
{
    public const GET = 'GET';
    public const POST = 'POST';
    public const PUT = 'PUT';
    public const PATCH = 'PATCH';
    public const HEAD = 'HEAD';
    public const DELETE = 'DELETE';
    public const OPTIONS = 'OPTIONS';
    public const ALL = '*';

    private const ALLOWED_VERBS = [
        self::GET,
        self::POST,
        self::PUT,
        self::PATCH,
        self::HEAD,
        self::DELETE,
        self::OPTIONS,
        self::ALL,
    ];

    public const TYPE_WEBSOCKET = 'websocket';
    public const TYPE_HTTP_REST = 'http';
    public const TYPE_AUTHORIZERS = 'authorizers';

    public string $type = '';
    public string $apiId = '';
    public string $stage = '';
    public string $verb = '';
    public string $path = '';

    public static function http(
        string $verb = '*',
        string $path = '*',
        string $stage = '*',
        string $apiId = '*',
        string $region = '',
        string $accountId = '',
    ): self {
        if (!in_array($verb, self::ALLOWED_VERBS, true)) {
            throw new \InvalidArgumentException('Not a valid http verb');
        }
        $resource = implode('/', [$apiId, $stage, $verb, ltrim($path, '/')]);
        return new self(
            'aws',
            'execute-api',
            $region,
            $accountId,
            $resource,
        );
    }

    protected function parseResource(string $resource): void
    {
        $parts = explode('/', $resource, 4);
        $this->apiId = $parts[0];
        $this->stage = $parts[1];
        $this->type = match ($this->stage) {
            'authorizers' => self::TYPE_AUTHORIZERS,
            default => self::TYPE_WEBSOCKET,
        };
        if (isset($parts[3])) {
            $this->type = self::TYPE_HTTP_REST;
            $this->verb = strtoupper($parts[2]);
            if (!in_array($this->verb, self::ALLOWED_VERBS, true)) {
                throw new \InvalidArgumentException('Invalid http verb');
            }
        }
        $this->path = $parts[array_key_last($parts)];
    }
}
