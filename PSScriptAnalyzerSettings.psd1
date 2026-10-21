@{
    # PSScriptAnalyzer settings — WinSecHunter
    # Severity gate in CI: Error fails the build; warnings are reported and
    # triaged (see IncludeRules for the enforced quality bar).

    IncludeRules = @(
        'PSAvoidUsingCmdletAliases'
        'PSAvoidUsingComputerNameHardcoded'
        'PSAvoidUsingConvertToSecureStringWithPlainText'
        'PSAvoidUsingDoubleQuotesForConstantString'
        'PSAvoidUsingEmptyCatchBlock'
        'PSAvoidUsingInvokeExpression'
        'PSAvoidUsingPlainTextForPassword'
        'PSAvoidUsingPositionalParameters'
        'PSAvoidUsingUserNameAndPassWordParams'
        'PSAvoidUsingWMICmdlet'
        'PSAvoidUsingWriteHost'
        'PSMissingModuleManifestField'
        'PSPossibleIncorrectComparisonWithNull'
        'PSPossibleIncorrectUsageOfAssignmentOperator'
        'PSPossibleIncorrectUsageOfRedirectionOperator'
        'PSProvideCommentHelp'
        'PSReservedCmdletChar'
        'PSReservedParams'
        'PSUseApprovedVerbs'
        'PSUseCmdletCorrectly'
        'PSUseOutputTypeCorrectly'
        'PSUsePSCredentialType'
        'PSUseShouldProcessForStateChangingFunctions'
        'PSUseSingularNouns'
    )

    ExcludeRules = @(
        # Verbose-but-harmless style rule; would churn the codebase without value.
        'PSAvoidUsingDoubleQuotesForConstantString',
        # Classes/enums live in module scope and are dot-sourced at import;
        # the analyzer parses files in isolation and cannot resolve the types.
        # Real type errors are caught by the Pester import/parse tests instead.
        'TypeNotFound'
    )

    Rules = @{
        PSUseCompatibleCmdlets = @{ Enable = $false }
        PSUseSingularNouns     = @{ Enable = $true }
        PSAvoidUsingCmdletAliases = @{
            Enable = $true
            Allowlist = @()
        }
        PSProvideCommentHelp = @{
            Enable                  = $true
            ExportedCommandsOnly    = $true
            BlockComment            = $true
        }
    }
}
