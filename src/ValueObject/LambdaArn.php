<?php declare(strict_types=1);

namespace Sunkan\AwsAuthPolicy\ValueObject;

final class LambdaArn extends Arn
{
    public const TYPE_LAYER = 'layer';
    public const TYPE_FUNCTION = 'function';
    public const TYPE_EVENT_SOURCE_MAPPING = 'event-source-mapping';

    public string $type = '';
    public string $layer = '';
    public string $function = '';
    public string $eventSourceMappingId = '';
    public string $version = '';
    public string $alias = '';

    protected function parseResource(string $resource): void
    {
        $parts = explode(':', $resource);
        $this->type = strtolower($parts[0]);
        if ($this->type === 'function') {
            $this->function = $parts[1];
            if (isset($parts[2])) {
                if (is_numeric($parts[2])) {
                    $this->version = $parts[2];
                }
                else {
                    $this->alias = $parts[2];
                }
            }
        }
        elseif ($this->type === 'layer') {
            $this->layer = $parts[1];
            if (isset($parts[2])) {
                $this->version = $parts[2];
            }
        }
        elseif ($this->type === 'event-source-mapping') {
            $this->eventSourceMappingId = $parts[1];
        }
    }
}
