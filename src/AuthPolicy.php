<?php declare(strict_types=1);

namespace Sunkan\AwsAuthPolicy;

use Sunkan\AwsAuthPolicy\ValueObject\Arn;
use Sunkan\AwsAuthPolicy\ValueObject\ExecuteApiArn;

final class AuthPolicy implements \JsonSerializable
{
    private const VERSION = '2012-10-17';

    public const ALLOW = 'Allow';
    public const DENY = 'Deny';

    public const GET = 'GET';
    public const POST = 'POST';
    public const PUT = 'PUT';
    public const PATCH = 'PATCH';
    public const HEAD = 'HEAD';
    public const DELETE = 'DELETE';
    public const OPTIONS = 'OPTIONS';
    public const ALL = '*';

    /** @var array<int, array{effect: string, arn: Arn, conditions: null|mixed[]}> */
    private array $statements = [];
    /** @var list<ResourcePolicy> */
    private array $resourcePolicies = [];

    private string $region;
    private string $stage;
    private string $apiId;

    public static function fromMethodArn(ExecuteApiArn|string $arn, string $principal = 'me'): self
    {
        if (is_string($arn)) {
            $arn = Arn::fromString($arn);
        }
        if (!$arn instanceof ExecuteApiArn) {
            throw new \InvalidArgumentException('Invalid arn. Expect ExecuteApiArn');
        }
        return new self(
            $principal,
            $arn->accountId ?? '*',
            [
                'region' => $arn->region ?: '*',
                'stage' => $arn->stage ?: '*',
                'apiId' => $arn->apiId ?: '*',
            ]
        );
    }

    /**
     * @param array{region?:string, stage?:string, apiId?:string} $options
     */
    public function __construct(
        private readonly string $principal,
        private readonly string $accountId,
        private readonly array $options,
    ) {
        $this->region = $this->options['region'] ?? '*';
        $this->stage = $this->options['stage'] ?? '*';
        $this->apiId = $this->options['apiId'] ?? '*';
    }

    public function allowAll(): void
    {
        $this->add(
            self::ALLOW,
            self::ALL,
            self::ALL,
        );
    }

    public function denyAll(): void
    {
        $this->add(
            self::DENY,
            self::ALL,
            self::ALL,
        );
    }

    /**
     * @param mixed[]|null $conditions
     */
    public function allow(
        string $verb,
        string $resource = self::ALL,
        ?array $conditions = null,
    ): void {
        $this->add(
            self::ALLOW,
            $verb,
            $resource,
            $conditions,
        );
    }

    /**
     * @param mixed[]|null $conditions
     */
    public function allowArn(Arn|string $arn, ?array $conditions = null): void
    {
        $this->addArn(self::ALLOW, $arn, $conditions);
    }

    /**
     * @param mixed[]|null $conditions
     */
    public function deny(
        string $verb,
        string $resource = self::ALL,
        ?array $conditions = null,
    ): void {
        $this->add(
            self::DENY,
            $verb,
            $resource,
            $conditions,
        );
    }

    /**
     * @param mixed[]|null $conditions
     */
    public function denyArn(Arn|string $arn, ?array $conditions = null): void
    {
        $this->addArn(self::DENY, $arn, $conditions);
    }

    public function addResourcePolicy(ResourcePolicy $policy): void
    {
        $this->resourcePolicies[] = $policy;
    }

    /**
     * @return mixed[]
     */
    public function build(): array
    {
        foreach ($this->resourcePolicies as $resourcePolicy) {
            $resourcePolicy->configurePolicy($this);
        }

        if (!$this->statements) {
            throw new \RuntimeException('No statements defined in policy');
        }

        $policy = [];
        $policy['principalId'] = $this->principal;
        $statements = [];
        $effectStatements = [
            self::ALLOW => [
                'Action' => 'execute-api:Invoke',
                'Effect' => self::ALLOW,
                'Resource' => [],
            ],
            self::DENY => [
                'Action' => 'execute-api:Invoke',
                'Effect' => self::DENY,
                'Resource' => [],
            ],
        ];
        foreach ($this->statements as $method) {
            if ($method['conditions']) {
                $statements[] = [
                    'Action' => 'execute-api:Invoke',
                    'Effect' => $method['effect'],
                    'Resource' => [$method['arn']->toString()],
                    'Condition' => $method['conditions'],
                ];
            }
            else {
                $effectStatements[$method['effect']]['Resource'][] = $method['arn']->toString();
            }
        }

        foreach ($effectStatements as $stmts) {
            if (!count($stmts['Resource'])) {
                continue;
            }
            $statements[] = $stmts;
        }

        $policy['policyDocument'] = [
            'Version' => self::VERSION,
            'Statement' => $statements,
        ];

        return $policy;
    }

    /**
     * @param mixed[]|null $conditions
     */
    private function addArn(string $effect, string|Arn $arn, ?array $conditions): void
    {
        if (!$arn instanceof Arn) {
            $arn = Arn::fromString($arn);
        }
        $this->statements[] = [
            'effect' => $effect,
            'arn' => $arn,
            'conditions' => $conditions,
        ];
    }

    /**
     * @param mixed[]|null $conditions
     */
    private function add(
        string $effect,
        string $verb,
        string $resource,
        ?array $conditions = null,
    ): void {
        $this->addArn($effect, ExecuteApiArn::http(
            $verb,
            ltrim($resource, '/'),
            $this->stage,
            $this->apiId,
            $this->region,
            $this->accountId,
        ), $conditions);
    }

    public function jsonSerialize(): mixed
    {
        return $this->build();
    }

    public function isEmpty(): bool
    {
        return !$this->statements;
    }
}
