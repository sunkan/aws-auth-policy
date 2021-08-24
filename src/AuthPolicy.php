<?php declare(strict_types=1);

namespace Sunkan\AwsAuthPolicy;

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

    /** @var array<int, array{effect: string, arn: string, conditions: null|mixed[]}> */
    private array $statements = [];
    /** @var ResourcePolicy[] */
    private array $resourcePolicies = [];

    private string $region;
    private string $stage;
    private string $apiId;

    public static function fromMethodArn(string $arn, string $principal = 'me'): self
    {
        [$iam, $stage] = explode('/', $arn);
        [, , , $region, $accountId, $apiId] = explode(':', $iam);
        return new self($principal, $accountId, [
            'region' => $region,
            'stage' => $stage,
            'apiId' => $apiId,
        ]);
    }

    /**
     * @param array{region?:string, stage?:string, apiId?:string} $options
     */
    public function __construct(
        private string $principal,
        private string $accountId,
        private array $options,
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
    public function allow(string $verb, string $resource = self::ALL, ?array $conditions = null): void
    {
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
    public function allowArn(string $arn, ?array $conditions = null): void
    {
        $this->addArn(self::ALLOW, $arn, $conditions);
    }

    /**
     * @param mixed[]|null $conditions
     */
    public function deny(string $verb, string $resource = self::ALL, ?array $conditions = null): void
    {
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
    public function denyArn(string $arn, ?array $conditions = null): void
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
                    'Resource' => [$method['arn']],
                    'Condition' => $method['conditions'],
                ];
            }
            else {
                $effectStatements[$method['effect']]['Resource'][] = $method['arn'];
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
    private function addArn(string $effect, string $arn, ?array $conditions): void
    {
        if (!str_starts_with($arn, 'arn:')) {
            throw new \InvalidArgumentException('Arn need to have the following format "arn:%s:%s:%s:%d:%s/%s/%s/%s"');
        }
        $arnPartCount = substr_count($arn, ':');
        $arnParts = explode(':', $arn);
        [,,$verb] = explode('/', $arnParts[$arnPartCount], 4);

        if (!in_array($verb, self::ALLOWED_VERBS, true)) {
            throw new \InvalidArgumentException('Not a valid http verb');
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
    private function add(string $effect, string $verb, string $resource, ?array $conditions = null): void
    {
        if (!in_array($verb, self::ALLOWED_VERBS, true)) {
            throw new \InvalidArgumentException('Not a valid http verb');
        }

        if ($resource[0] === '/') {
            $resource = substr($resource, 1);
        }

        $arnPrefix = implode(':', [
            'arn:aws:execute-api',
            $this->region,
            $this->accountId,
            $this->apiId,
        ]);
        $resourceArn = implode('/', [
            $arnPrefix,
            $this->stage,
            $verb,
            $resource,
        ]);

        $this->statements[] = [
            'effect' => $effect,
            'arn' => $resourceArn,
            'conditions' => $conditions,
        ];
    }

    public function jsonSerialize()
    {
        return $this->build();
    }
}
