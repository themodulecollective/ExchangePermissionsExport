# ExchangePermissionsExport

PowerShell Module for Improved Permissions Export Functions to Support Exchange Migrations including upgrades, on-premises to on-premises, on-premises to online, online to online, etc. Exported permissions can be used for permission replay for migrations and/or for analysis of user relationships for migration batching.

This module improves on soyalejolopez/Find-MailboxDelegates to improve output so that it is coherent and consistent across permission types and Exchange Organizations whether they are in Exchange Online or Exchange On Premises.  It also fixes a number of performance and logical errors compared to Find-MailboxDelegates and provides more modular code for easier troubleshooting and improvement.

This module does not provide permissions analysis for migration batching.  Instead, another module will do that entitled ExchangePermissionsAnalysis.