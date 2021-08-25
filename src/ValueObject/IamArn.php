<?php declare(strict_types=1);

namespace Sunkan\AwsAuthPolicy\ValueObject;

final class IamArn extends Arn
{
    public const TYPE_ROOT = 'root';
    public const TYPE_USER = 'user';
    public const TYPE_GROUP = 'group';
    public const TYPE_ROLE = 'role';
    public const TYPE_POLICY = 'policy';
    public const TYPE_MFA = 'mfa';
    public const TYPE_U2F = 'u2f';
    public const TYPE_INSTANCE_PROFILE = 'instance-profile';
    public const TYPE_FEDERATED_USER = 'federated-user';
    public const TYPE_SERVER_CERTIFICATE = 'server-certificate';
    public const TYPE_SAML_PROVIDER = 'saml-provider';
    public const TYPE_OIDC_PROVIDER = 'oidc-provider';
    public const TYPE_ASSUMED_ROLE = 'assumed-role';

    public bool $root = false;
    public string $type = '';
    public string $path = '';
    public string $name = '';

    public function parseResource(string $resource): void
    {
        if ($resource === self::TYPE_ROOT) {
            $this->root = true;
            $this->type = self::TYPE_ROOT;
        }
        else {
            [$this->type, $this->path] = explode('/', $resource, 2);
            $pathParts = explode('/', $this->path);
            $this->name = $pathParts[array_key_last($pathParts)] ?? '';
        }
    }
}
