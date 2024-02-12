<?php declare(strict_types=1);

namespace Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Sunkan\AwsAuthPolicy\ValueObject\Arn;
use Sunkan\AwsAuthPolicy\ValueObject\ExecuteApiArn;
use Sunkan\AwsAuthPolicy\ValueObject\IamArn;
use Sunkan\AwsAuthPolicy\ValueObject\LambdaArn;
use Sunkan\AwsAuthPolicy\ValueObject\S3Arn;

final class ArnTest extends TestCase
{
    public function testInvalidArn(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $arn = 'aws:s3:::examplebucket/developers/design_info.doc';
        Arn::fromString($arn);
    }

    public function testDefaultArnClass(): void
    {
        $arn = 'arn:aws:cloudformation:eu-west-1:123456789012:changeSet/Name-Of-ChangeSet/ed6c6f7f-688f-4e2b-9cf3-0e6fd4fb4cda';
        $arnObject = Arn::fromString($arn);

        $this->assertSame($arn, $arnObject->toString());

        $this->assertSame('cloudformation', $arnObject->service);
        $this->assertSame('eu-west-1', $arnObject->region);
    }

    public function testPartialArn(): void
    {
        $arn = 'arn:aws:s3:::examplebucket/developers/design_info.doc';
        $arnObject = Arn::fromString($arn);

        $this->assertSame('', $arnObject->region);
        $this->assertSame('', $arnObject->accountId);

        $this->assertSame($arn, $arnObject->toString());
    }

    public function testS3Arn(): void
    {
        $arn = 'arn:aws:s3:eu-west-1:123456789:bucket/path/object';
        $arnObject = Arn::fromString($arn);

        $this->assertInstanceOf(S3Arn::class, $arnObject);
        /** @var S3Arn $arnObject */

        $this->assertSame('bucket', $arnObject->bucket);
        $this->assertSame('path/object', $arnObject->path);

        $this->assertSame($arn, (string)$arnObject);
    }

    public function testExecuteApiArn(): void
    {
        $arn = 'arn:aws:execute-api:eu-west-1:50505050:dn1gh3pza2/prod/GET/view-article/1';
        $arnObject = Arn::fromString($arn);

        $this->assertInstanceOf(ExecuteApiArn::class, $arnObject);
        /** @var ExecuteApiArn $arnObject */

        $this->assertSame('prod', $arnObject->stage);
        $this->assertSame('GET', $arnObject->verb);
        $this->assertSame('view-article/1', $arnObject->path);
        $this->assertSame(ExecuteApiArn::TYPE_HTTP_REST, $arnObject->type);

        $this->assertSame($arn, (string)$arnObject);
    }

    public function testExecuteApiRouteKey(): void
    {
        $arn = 'arn:aws:execute-api:eu-west-1:50505050:lka12jk12d/prod/test-resource';
        $arnObject = Arn::fromString($arn);

        $this->assertInstanceOf(ExecuteApiArn::class, $arnObject);
        /** @var ExecuteApiArn $arnObject */

        $this->assertSame('prod', $arnObject->stage);
        $this->assertSame('', $arnObject->verb);
        $this->assertSame('test-resource', $arnObject->path);
        $this->assertSame(ExecuteApiArn::TYPE_WEBSOCKET, $arnObject->type);

        $this->assertSame($arn, (string)$arnObject);
    }

    public function testExecuteApiAuthorizers(): void
    {
        $arn = 'arn:aws:execute-api:eu-west-1:50505050:lka12jk12d/authorizers/test-authorizers';
        $arnObject = Arn::fromString($arn);

        $this->assertInstanceOf(ExecuteApiArn::class, $arnObject);
        /** @var ExecuteApiArn $arnObject */

        $this->assertSame('authorizers', $arnObject->stage);
        $this->assertSame('test-authorizers', $arnObject->path);
        $this->assertSame(ExecuteApiArn::TYPE_AUTHORIZERS, $arnObject->type);

        $this->assertSame($arn, (string)$arnObject);
    }

    public function testExecuteApiInvalidArn(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        $arn = 'arn:aws:execute-api:eu-west-1:50505050:dn1gh3pza2/prod/WRONG/view-article/1';
        Arn::fromString($arn);
    }

    public function testExecuteApiHttpConstructor(): void
    {
        $arnObj = ExecuteApiArn::http(ExecuteApiArn::GET, '/article/1');

        $this->assertSame('arn:aws:execute-api:::*/*/GET/article/1', $arnObj->toString());
    }

    public function testExecuteApiHttpConstructorWithInvalidVerb(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        ExecuteApiArn::http('WRONG_VERB');
    }

    public function testLambdaFunction(): void
    {
        $arn = 'arn:aws:lambda:us-west-2:123456789012:function:my-function';
        $arnObject = Arn::fromString($arn);

        $this->assertInstanceOf(LambdaArn::class, $arnObject);
        /** @var LambdaArn $arnObject */

        $this->assertSame(LambdaArn::TYPE_FUNCTION, $arnObject->type);
        $this->assertSame('my-function', $arnObject->function);
        $this->assertSame('', $arnObject->version);
        $this->assertSame('', $arnObject->alias);

        $this->assertSame($arn, (string)$arnObject);
    }

    public function testLambdaFunctionWithVersion(): void
    {
        $arn = 'arn:aws:lambda:us-west-2:123456789012:function:my-function:32';
        $arnObject = Arn::fromString($arn);

        $this->assertInstanceOf(LambdaArn::class, $arnObject);
        /** @var LambdaArn $arnObject */

        $this->assertSame(LambdaArn::TYPE_FUNCTION, $arnObject->type);
        $this->assertSame('my-function', $arnObject->function);
        $this->assertSame('32', $arnObject->version);
        $this->assertSame('', $arnObject->alias);

        $this->assertSame($arn, (string)$arnObject);
    }

    public function testLambdaFunctionWithAlias(): void
    {
        $arn = 'arn:aws:lambda:us-west-2:123456789012:function:my-function:TEST';
        $arnObject = Arn::fromString($arn);

        $this->assertInstanceOf(LambdaArn::class, $arnObject);
        /** @var LambdaArn $arnObject */

        $this->assertSame(LambdaArn::TYPE_FUNCTION, $arnObject->type);
        $this->assertSame('my-function', $arnObject->function);
        $this->assertSame('', $arnObject->version);
        $this->assertSame('TEST', $arnObject->alias);

        $this->assertSame($arn, (string)$arnObject);
    }

    public function testLambdaEventSourceMapping(): void
    {
        $arn = 'arn:aws:lambda:us-west-2:123456789012:event-source-mapping:fa123456-14a1-4fd2-9fec-83de64ad683de6d47';
        $arnObject = Arn::fromString($arn);

        $this->assertInstanceOf(LambdaArn::class, $arnObject);
        /** @var LambdaArn $arnObject */

        $this->assertSame(LambdaArn::TYPE_EVENT_SOURCE_MAPPING, $arnObject->type);
        $this->assertSame('fa123456-14a1-4fd2-9fec-83de64ad683de6d47', $arnObject->eventSourceMappingId);
        $this->assertSame('', $arnObject->version);

        $this->assertSame($arn, (string)$arnObject);
    }

    public function testLambdaLayerWithVersion(): void
    {
        $arn = 'arn:aws:lambda:eu-west-1:123456789:Layer:my-layer:42';
        $arnObject = Arn::fromString($arn);

        $this->assertInstanceOf(LambdaArn::class, $arnObject);
        /** @var LambdaArn $arnObject */

        $this->assertSame(LambdaArn::TYPE_LAYER, $arnObject->type);
        $this->assertSame('my-layer', $arnObject->layer);
        $this->assertSame('42', $arnObject->version);

        $this->assertSame($arn, (string)$arnObject);
    }

    public function testIamRoot(): void
    {
        $arn = 'arn:aws:iam::account:root';
        $arnObject = Arn::fromString($arn);

        $this->assertInstanceOf(IamArn::class, $arnObject);
        /** @var IamArn $arnObject */

        $this->assertTrue($arnObject->root);
        $this->assertSame(IamArn::TYPE_ROOT, $arnObject->type);
    }

    #[DataProvider('iamTypes')]
    public function testIamTypes(string $arn, string $type, string $name, string $path): void
    {
        $arnObject = Arn::fromString($arn);

        $this->assertInstanceOf(IamArn::class, $arnObject);
        /** @var IamArn $arnObject */

        $this->assertFalse($arnObject->root);
        $this->assertSame($type, $arnObject->type);
        $this->assertSame($name, $arnObject->name);
        $this->assertSame($path, $arnObject->path);
    }

    /**
     * @return string[][]
     */
    public static function iamTypes(): array
    {
        return [
            [
                'arn:aws:iam::123456789012:user/JohnDoe',
                IamArn::TYPE_USER,
                'JohnDoe',
                'JohnDoe',
            ],
            [
                'arn:aws:iam::123456789012:user/division_abc/subdivision_xyz/JaneDoe',
                IamArn::TYPE_USER,
                'JaneDoe',
                'division_abc/subdivision_xyz/JaneDoe',
            ],
            [
                'arn:aws:iam::123456789012:group/Developers',
                IamArn::TYPE_GROUP,
                'Developers',
                'Developers',
            ],
            [
                'arn:aws:iam::123456789012:group/division_abc/subdivision_xyz/product_A/Developers',
                IamArn::TYPE_GROUP,
                'Developers',
                'division_abc/subdivision_xyz/product_A/Developers',
            ],
            [
                'arn:aws:iam::123456789012:role/S3Access',
                IamArn::TYPE_ROLE,
                'S3Access',
                'S3Access',
            ],
            [
                'arn:aws:iam::123456789012:role/application_abc/component_xyz/RDSAccess',
                IamArn::TYPE_ROLE,
                'RDSAccess',
                'application_abc/component_xyz/RDSAccess',
            ],
            [
                'arn:aws:iam::123456789012:role/aws-service-role/access-analyzer.amazonaws.com/AWSServiceRoleForAccessAnalyzer',
                IamArn::TYPE_ROLE,
                'AWSServiceRoleForAccessAnalyzer',
                'aws-service-role/access-analyzer.amazonaws.com/AWSServiceRoleForAccessAnalyzer',
            ],
            [
                'arn:aws:iam::123456789012:role/service-role/QuickSightAction',
                IamArn::TYPE_ROLE,
                'QuickSightAction',
                'service-role/QuickSightAction',
            ],
            [
                'arn:aws:iam::123456789012:policy/UsersManageOwnCredentials',
                IamArn::TYPE_POLICY,
                'UsersManageOwnCredentials',
                'UsersManageOwnCredentials',
            ],
            [
                'arn:aws:iam::123456789012:policy/division_abc/subdivision_xyz/UsersManageOwnCredentials',
                IamArn::TYPE_POLICY,
                'UsersManageOwnCredentials',
                'division_abc/subdivision_xyz/UsersManageOwnCredentials',
            ],
            [
                'arn:aws:iam::123456789012:instance-profile/Webserver',
                IamArn::TYPE_INSTANCE_PROFILE,
                'Webserver',
                'Webserver',
            ],
            [
                'arn:aws:sts::123456789012:federated-user/JohnDoe',
                IamArn::TYPE_FEDERATED_USER,
                'JohnDoe',
                'JohnDoe',
            ],
            [
                'arn:aws:sts::123456789012:assumed-role/Accounting-Role/JaneDoe',
                IamArn::TYPE_ASSUMED_ROLE,
                'JaneDoe',
                'Accounting-Role/JaneDoe',
            ],
            [
                'arn:aws:iam::123456789012:mfa/JaneDoeMFA',
                IamArn::TYPE_MFA,
                'JaneDoeMFA',
                'JaneDoeMFA',
            ],
            [
                'arn:aws:iam::123456789012:u2f/user/JohnDoe/default (U2F security key)',
                IamArn::TYPE_U2F,
                'default (U2F security key)',
                'user/JohnDoe/default (U2F security key)',
            ],
            [
                'arn:aws:iam::123456789012:server-certificate/ProdServerCert',
                IamArn::TYPE_SERVER_CERTIFICATE,
                'ProdServerCert',
                'ProdServerCert',
            ],
            [
                'arn:aws:iam::123456789012:server-certificate/division_abc/subdivision_xyz/ProdServerCert',
                IamArn::TYPE_SERVER_CERTIFICATE,
                'ProdServerCert',
                'division_abc/subdivision_xyz/ProdServerCert',
            ],
            [
                'arn:aws:iam::123456789012:saml-provider/ADFSProvider',
                IamArn::TYPE_SAML_PROVIDER,
                'ADFSProvider',
                'ADFSProvider',
            ],
            [
                'arn:aws:iam::123456789012:oidc-provider/GoogleProvider',
                IamArn::TYPE_OIDC_PROVIDER,
                'GoogleProvider',
                'GoogleProvider',
            ],
        ];
    }
}
