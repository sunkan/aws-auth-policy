<?php declare(strict_types=1);

namespace Tests;

use PHPUnit\Framework\TestCase;
use Sunkan\AwsAuthPolicy\AuthPolicy;
use Sunkan\AwsAuthPolicy\ResourcePolicy;
use Sunkan\AwsAuthPolicy\ValueObject\Arn;
use Sunkan\AwsAuthPolicy\ValueObject\ExecuteApiArn;
use Tests\Stub\StubResourcePolicy;

final class AuthPolicyTest extends TestCase
{
    public function testAllowAll(): void
    {
        $policy = new AuthPolicy(
            'me',
            '50505050',
            [
                'region' => 'eu-west-1',
                'stage' => 'prod',
            ],
        );

        $policy->allowAll();

        self::assertSame([
            'principalId' => 'me',
            'policyDocument' => [
                'Version' => '2012-10-17',
                'Statement' => [
                    [
                        'Action' => 'execute-api:Invoke',
                        'Effect' => 'Allow',
                        'Resource' => [
                            'arn:aws:execute-api:eu-west-1:50505050:*/prod/*/*',
                        ],
                    ],
                ],
            ],
        ], $policy->build());
    }

    public function testDenyAll(): void
    {
        $policy = new AuthPolicy(
            'me',
            '50505050',
            [
                'region' => 'eu-west-1',
                'stage' => 'prod',
            ],
        );

        $policy->denyAll();

        self::assertSame([
            'principalId' => 'me',
            'policyDocument' => [
                'Version' => '2012-10-17',
                'Statement' => [
                    [
                        'Action' => 'execute-api:Invoke',
                        'Effect' => 'Deny',
                        'Resource' => [
                            'arn:aws:execute-api:eu-west-1:50505050:*/prod/*/*',
                        ],
                    ],
                ],
            ],
        ], $policy->build());
    }

    public function testAllowResource(): void
    {
        $policy = new AuthPolicy(
            'me',
            '50505050',
            [
                'region' => 'eu-west-1',
                'stage' => 'prod',
            ],
        );

        $policy->allow(AuthPolicy::GET, '/view-article');

        self::assertSame([
            'principalId' => 'me',
            'policyDocument' => [
                'Version' => '2012-10-17',
                'Statement' => [
                    [
                        'Action' => 'execute-api:Invoke',
                        'Effect' => 'Allow',
                        'Resource' => [
                            'arn:aws:execute-api:eu-west-1:50505050:*/prod/GET/view-article',
                        ],
                    ],
                ],
            ],
        ], $policy->build());
    }

    public function testMixOfResources(): void
    {
        $policy = new AuthPolicy(
            'me',
            '50505050',
            [
                'region' => 'eu-west-1',
                'stage' => 'prod',
            ],
        );

        $policy->allow(AuthPolicy::GET, '/view-article');
        $policy->allow(AuthPolicy::PUT, '/update-article');
        $policy->deny(AuthPolicy::DELETE, '/delete-article');

        self::assertSame([
            'principalId' => 'me',
            'policyDocument' => [
                'Version' => '2012-10-17',
                'Statement' => [
                    [
                        'Action' => 'execute-api:Invoke',
                        'Effect' => 'Allow',
                        'Resource' => [
                            'arn:aws:execute-api:eu-west-1:50505050:*/prod/GET/view-article',
                            'arn:aws:execute-api:eu-west-1:50505050:*/prod/PUT/update-article',
                        ],
                    ], [
                        'Action' => 'execute-api:Invoke',
                        'Effect' => 'Deny',
                        'Resource' => [
                            'arn:aws:execute-api:eu-west-1:50505050:*/prod/DELETE/delete-article',
                        ],
                    ],
                ],
            ],
        ], $policy->build());
    }

    public function testAllowResourceWithCondition(): void
    {
        $policy = new AuthPolicy(
            'me',
            '50505050',
            [
                'region' => 'eu-west-1',
                'stage' => 'prod',
            ],
        );

        $policy->allow(
            AuthPolicy::GET,
            '/view-article',
            [
                'NumericLessThanEquals' => [
                    "aws:MultiFactorAuthAge" => "3600"
                ],
            ],
        );

        self::assertSame([
            'principalId' => 'me',
            'policyDocument' => [
                'Version' => '2012-10-17',
                'Statement' => [
                    [
                        'Action' => 'execute-api:Invoke',
                        'Effect' => 'Allow',
                        'Resource' => [
                            'arn:aws:execute-api:eu-west-1:50505050:*/prod/GET/view-article',
                        ],
                        'Condition' => [
                            'NumericLessThanEquals' => [
                                "aws:MultiFactorAuthAge" => "3600"
                            ],
                        ],
                    ],
                ],
            ],
        ], $policy->build());
    }

    public function testCantGenerateEmptyPolicy(): void
    {
        $policy = new AuthPolicy(
            'me',
            '50505050',
            [],
        );

        $this->expectException(\RuntimeException::class);

        $policy->build();
    }

    public function testJsonSerializeIsSameAsBuild(): void
    {
        $policy = new AuthPolicy(
            'me',
            '50505050',
            [
                'region' => 'eu-west-1',
                'stage' => 'prod',
            ],
        );

        $policy->allowAll();

        $this->assertSame($policy->build(), $policy->jsonSerialize());
    }

    public function testFromMethodArnConstructor(): void
    {
        $policy = AuthPolicy::fromMethodArn('arn:aws:execute-api:eu-west-1:50505050:lka12jk12d/prod/test-resource');
        $policy->allowAll();

        self::assertSame([
            'principalId' => 'me',
            'policyDocument' => [
                'Version' => '2012-10-17',
                'Statement' => [
                    [
                        'Action' => 'execute-api:Invoke',
                        'Effect' => 'Allow',
                        'Resource' => [
                            'arn:aws:execute-api:eu-west-1:50505050:lka12jk12d/prod/*/*',
                        ],
                    ],
                ],
            ],
        ], $policy->build());
    }

    public function testResourcePolicy(): void
    {
        $policy = new AuthPolicy(
            'me',
            '50505050',
            [
                'region' => 'eu-west-1',
                'stage' => 'prod',
            ],
        );

        $resourcePolicy = new StubResourcePolicy();

        $policy->addResourcePolicy($resourcePolicy);

        self::assertSame([
            'principalId' => 'me',
            'policyDocument' => [
                'Version' => '2012-10-17',
                'Statement' => [
                    [
                        'Action' => 'execute-api:Invoke',
                        'Effect' => 'Allow',
                        'Resource' => [
                            'arn:aws:execute-api:eu-west-1:50505050:*/prod/GET/test/path',
                        ],
                    ],
                ],
            ],
        ], $policy->build());
    }

    public function testAllowArn(): void
    {
        $policy = new AuthPolicy(
            'me',
            '50505050',
            [
                'region' => 'eu-west-1',
                'stage' => 'prod',
            ],
        );

        $arn = 'arn:aws:execute-api:eu-west-1:50505050:dn1gh3pza2/prod/GET/view-article/1';

        $policy->allowArn($arn);
        self::assertSame([
            'principalId' => 'me',
            'policyDocument' => [
                'Version' => '2012-10-17',
                'Statement' => [
                    [
                        'Action' => 'execute-api:Invoke',
                        'Effect' => 'Allow',
                        'Resource' => [
                            $arn,
                        ],
                    ],
                ],
            ],
        ], $policy->build());
    }

    public function testDenyArn(): void
    {
        $policy = new AuthPolicy(
            'me',
            '50505050',
            [
                'region' => 'eu-west-1',
                'stage' => 'prod',
            ],
        );

        $arn = 'arn:aws:execute-api:eu-west-1:50505050:dn1gh3pza2/prod/GET/view-article/1';

        $policy->denyArn($arn);

        self::assertFalse($policy->isEmpty());
        self::assertSame([
            'principalId' => 'me',
            'policyDocument' => [
                'Version' => '2012-10-17',
                'Statement' => [
                    [
                        'Action' => 'execute-api:Invoke',
                        'Effect' => 'Deny',
                        'Resource' => [
                            $arn,
                        ],
                    ],
                ],
            ],
        ], $policy->build());
    }

    /**
     * @dataProvider invalidArns
     */
    public function testInvalidArns(string $arn): void
    {
        $policy = new AuthPolicy(
            'me',
            '50505050',
            [],
        );


        $this->expectException(\InvalidArgumentException::class);

        $policy->denyArn($arn);
    }

    public function testIsEmpty(): void
    {
        $policy = new AuthPolicy(
            'me',
            '50505050',
            [],
        );

        self::assertTrue($policy->isEmpty());
    }

    /**
     * @return string[][]
     */
    public function invalidArns(): array
    {
        return [
            ['random-input'],
            ['arn:aws:execute-api:eu-west-1:50505050:dn1gh3pza2/prod/WRONG/view-article/1']
        ];
    }

    public function testCreatePolicyFromArn(): void
    {
        /** @var ExecuteApiArn $arn */
        $arn = Arn::fromString('arn:aws:execute-api:eu-west-1:50505050:lka12jk12d/prod/test-resource');
        $policy = AuthPolicy::fromMethodArn($arn);
        $policy->allowAll();

        self::assertSame([
            'principalId' => 'me',
            'policyDocument' => [
                'Version' => '2012-10-17',
                'Statement' => [
                    [
                        'Action' => 'execute-api:Invoke',
                        'Effect' => 'Allow',
                        'Resource' => [
                            'arn:aws:execute-api:eu-west-1:50505050:lka12jk12d/prod/*/*',
                        ],
                    ],
                ],
            ],
        ], $policy->build());
    }

    public function testCreateWithInvalidArn(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        AuthPolicy::fromMethodArn('arn:aws:lambda:eu-west-1:123456789:Layer:my-layer:42');
    }
}
