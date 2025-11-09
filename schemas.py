#!/usr/bin/env python3
"""
Input validation schemas using Marshmallow
Provides secure validation for Flask API endpoints
"""

from marshmallow import Schema, fields, validates, ValidationError, validate
import re


class ScanRequestSchema(Schema):
    """Schema for validating scan start requests"""
    target = fields.Str(
        required=True,
        validate=validate.Length(min=1, max=255),
        error_messages={"required": "Target is required"}
    )
    ports = fields.Str(
        required=False,
        missing="1-1000",
        validate=validate.Length(max=100)
    )
    modules = fields.List(
        fields.Str(validate=validate.OneOf([
            'network_scan',
            'dns_enum',
            'whois',
            'ssl_analysis',
            'vuln_scan',
            'social_intel',
            'advanced_dns',
            'cloud_assets'
        ])),
        required=True,
        validate=validate.Length(min=1),
        error_messages={"required": "At least one module must be selected"}
    )

    @validates('target')
    def validate_target(self, value):
        """Validate target is a valid domain, IP, or CIDR"""
        # Check for valid domain
        domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        # Check for valid IPv4
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        # Check for valid IPv4 CIDR
        cidr_pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
        # Check for valid IPv6
        ipv6_pattern = r'^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|::)$'
        
        if not (re.match(domain_pattern, value) or 
                re.match(ipv4_pattern, value) or 
                re.match(cidr_pattern, value) or
                re.match(ipv6_pattern, value)):
            raise ValidationError('Invalid target format. Must be a valid domain, IP address, or CIDR range.')
        
        # Additional IPv4 validation
        if re.match(ipv4_pattern, value):
            octets = value.split('.')
            for octet in octets:
                if int(octet) > 255:
                    raise ValidationError('Invalid IP address: octets must be 0-255')

    @validates('ports')
    def validate_ports(self, value):
        """Validate port specification"""
        # Allow single port, ranges, or comma-separated
        port_pattern = r'^(\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*)$'
        if not re.match(port_pattern, value):
            raise ValidationError('Invalid port specification. Use format: 80, 80-443, or 80,443,8080')
        
        # Validate port numbers are in valid range
        parts = value.replace('-', ',').split(',')
        for part in parts:
            port = int(part)
            if port < 1 or port > 65535:
                raise ValidationError('Port numbers must be between 1 and 65535')


class LoginSchema(Schema):
    """Schema for validating login requests"""
    username = fields.Str(
        required=True,
        validate=validate.Length(min=1, max=80),
        error_messages={"required": "Username is required"}
    )
    password = fields.Str(
        required=True,
        validate=validate.Length(min=1, max=255),
        error_messages={"required": "Password is required"}
    )

    @validates('username')
    def validate_username(self, value):
        """Validate username format"""
        # Only allow alphanumeric and underscore
        if not re.match(r'^[a-zA-Z0-9_]+$', value):
            raise ValidationError('Username must contain only letters, numbers, and underscores')


class ScanFilterSchema(Schema):
    """Schema for validating scan filter parameters"""
    status = fields.Str(
        required=False,
        validate=validate.OneOf(['pending', 'running', 'completed', 'failed'])
    )
    limit = fields.Int(
        required=False,
        validate=validate.Range(min=1, max=100),
        missing=10
    )
    offset = fields.Int(
        required=False,
        validate=validate.Range(min=0),
        missing=0
    )


# Helper function for schema validation
def validate_request_data(schema_class, data):
    """
    Validate request data against a schema
    
    Args:
        schema_class: Marshmallow Schema class
        data: Dictionary of data to validate
        
    Returns:
        Tuple of (validated_data, errors)
        If errors is not None, validation failed
    """
    schema = schema_class()
    try:
        validated_data = schema.load(data)
        return validated_data, None
    except ValidationError as err:
        return None, err.messages
