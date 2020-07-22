# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

Function ConvertTo-PythonPrimitiveType {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [AllowNull()]
        [Type]
        $InputObject
    )

    if (-not $InputObject) {
        return
    }

    switch ($InputObject.FullName) {
        System.String { 'PSString' }
        System.Char { 'PSChar' }
        System.Boolean { 'PSBool' }
        System.DateTime { 'PSDateTime' }
        System.TimeSpan { 'PSDuration' }
        System.Byte { 'PSByte' }
        System.SByte { 'PSSbyte' }
        System.UInt16 { 'PSUInt16' }
        System.Int16 { 'PSInt16' }
        System.UInt32 { 'PSUInt' }
        System.Int32 { 'PSInt' }
        System.UInt64 { 'PSUInt64' }
        System.Int64 { 'PSInt64' }
        System.Single { 'PSSingle' }
        System.Double { 'PSDouble' }
        System.Decimal { 'PSDecimal' }
        System.Byte[] { 'PSByteArray' }
        System.Guid { 'PSGuid' }
        System.Uri { 'PSUri' }
        System.Version { 'PSVersion' }
        System.Xml.XmlDocument { 'PSXml' }
        System.Management.Automation.ScriptBlock { 'PSScriptBlock' }
        System.Security.SecureString { 'PSSecureString' }
    }
}

Function ConvertTo-PythonClass {
    <#
    .SYNOPSIS
    Generates Python code to use as a skeleton for a .NET class implemented in Python.

    .PARAMETER InputObject
    The type or an instance of a type to make the skeleton for.

    .PARAMETER AddDoc
    Whether to add a Python doc string to the generated skeleton.

    .PARAMETER EnumAsHex
    Whether to format the enum values as a hex code and not a decimal.

    .PARAMETER Rehydrate
    Whether to mark the Python class as rehydrated or not.

    .NOTES
    It is recommended to use an instance of a type as '-InputObject'. Some properties are only added once the object
    has been initialised so passing by type may miss some.

    Do not use this to create a class for a 'PSCustomObject' instance.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [Object]
        $InputObject,

        [Switch]
        $AddDoc,

        [Switch]
        $EnumAsHex,

        [Switch]
        $Rehydrate
    )

    begin {
        $sb = New-Object -TypeName System.Text.StringBuilder

        $null = $sb.Append(@'
import pypsrp.dotnet as pynet


'@)
    }

    process {
        $type = $null
        $typeNames = [System.Collections.Generic.List[String]]@()
        $properties = [Ordered]@{
            adapted = [Ordered]@{}
            extended = [Ordered]@{}
        }
        $isEnum = $false

        if ($InputObject -is [Type]) {
            $type = $InputObject

            $baseType = $InputObject
            do {
                $typeNames.Add($baseType.FullName)
                $baseType = $baseType.BaseType
            } while ($baseType.BaseType)
            $typeNames.Add($baseType.FullName)

            if ($InputObject.IsSubclassOf([System.Enum])) {
                $isEnum = $true

            } else {
                foreach ($adapted in $InputObject.GetProperties()) {
                    $properties.adapted.Add($adapted.Name, $adapted.PropertyType)
                }

                foreach ($extended in (Get-TypeData -TypeName $InputObject.FullName).Members.GetEnumerator()) {
                    $name = $extended.Key
                    $data = $extended.Value

                    switch ($data.GetType().Name) {
                        AliasPropertyData {
                            $properties.extended.Add($name, $data.MemberType)
                        }
                        CodePropertyData {
                            $properties.extended.Add($name, $data.GetCodeReference.ReflectedType)
                        }
                        NotePropertyData {
                            $properties.extended.Add($name, $data.Value.GetType())
                        }
                        ScriptPropertyData {
                            # Cannot determine the type as a ScriptBlock could output anything.
                            $properties.extended.Add($name, $null)
                        }
                        default {}
                    }
                }
            }

        } else {
            $type = $InputObject.GetType()
            $typeNames = $InputObject.PSTypeNames

            if ($type.IsSubclassOf([System.Enum])) {
                $isEnum = $true

            } else {
                foreach ($adapted in $InputObject.PSAdapted.PSObject.Properties) {
                    $properties.adapted.Add($adapted.Name, $adapted.TypeNameOfValue -as [Type])
                }

                foreach ($extended in $InputObject.PSExtended.PSObject.Properties) {
                    $properties.extended.Add($extended.Name, $extended.TypeNameOfValue -as [Type])
                }
            }
        }

        $enumValues = [System.Collections.Generic.List[String]]@()
        if ($isEnum) {
            $rawType = [System.Enum]::GetUnderlyingType($type)
            foreach ($name in ([System.Enum]::GetValues($type))) {
                $rawName = $name.ToString()

                # None is a reserved character in Python, need to lowercase this
                if ($rawName -ceq 'None') {
                    $rawName = 'none'
                }
                $rawValue = $name -as $rawType

                if ($EnumAsHex) {
                    $hexLength = ("{0:X}" -f $rawType::MaxValue).Length

                    $rawValue = ("0x{0:X$($hexLength)}" -f $rawValue)
                }

                $enumValues.Add("$rawName = $rawValue")
            }


            if ($type.CustomAttributes | Where-Object { $_.AttributeType.FullName -eq 'System.FlagsAttribute' }) {
                $enumType = 'PSFlagBase'

            } else {
                $enumType = 'PSEnumBase'
            }

            $rawType = ConvertTo-PythonPrimitiveType -InputObject $rawType
            $null = $sb.AppendLine("`nclass PSEnum$($type.Name)(pynet.$enumType, pynet.$rawType):")

        } else {
            $null = $sb.AppendLine("`nclass PS$($type.Name)(pynet.PSObject):")
        }

        if ($AddDoc) {
            $null = $sb.AppendLine(@"
    """Python class for $($type.FullName)

    This is an auto-generated Python class for the $($type.FullName) .NET class.
    """
"@)
        }

        $null = $sb.AppendLine("    PSObject = pynet.PSObjectMeta(")

        # Define the object's types
        $null = $sb.AppendLine("        type_names=[")
        foreach ($name in $typeNames) {
            $null = $sb.AppendLine("            '$name',")

        }
        $null = $sb.AppendLine("        ],")

        foreach ($propType in $properties.GetEnumerator()) {
            if (-not $propType.Value.Count) {
                continue
            }

            $null = $sb.AppendLine("        $($propType.Key)_properties=[")
            foreach ($prop in $propType.Value.GetEnumerator()) {
                $psType = ConvertTo-PythonPrimitiveType -InputObject $prop.Value

                $typeValue = $null
                if ($psType) {
                    $typeValue = ", ps_type=$psType"
                }
                $null = $sb.AppendLine("            pynet.PSPropertyInfo('$($prop.Key)'$typeValue),")
            }

            $null = $sb.AppendLine("        ],")
        }

        if ($Rehydrate) {
            $null = $sb.AppendLine("        rehydrate=True,")
        }

        $null = $sb.AppendLine("    )`n")

        if ($enumValues) {
            foreach ($enumValue in $enumValues) {
                $null = $sb.AppendLine("    $enumValue")
            }
            $null = $sb.AppendLine()
        }
    }

    end {
        $sb.ToString()
    }
}
