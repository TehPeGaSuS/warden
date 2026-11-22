# Warden `rpc_message` RPC interface

> [!NOTE]
> The old Anope names (`anope.*`, e.g. `anope.listAccounts`) still work and map to the `warden.*` methods below; RPC tokens that list `anope.*` methods also keep working. They are deprecated and will be removed in a later release.

## `warden.messageNetwork`

Sends a message to all users on the network.

### Parameters

Index | Description
----- | -----------
0+    | One or more messages to send.

### Errors

Code   | Description
------ | -----------
-32099 | The global service is not available.

### Result

This procedure returns no result.

## `warden.messageServer`

Sends a message to all users on the specified server.

### Parameters

Index | Description
----- | -----------
0     | The name of the server to message users on.
1+    | One or more messages to send.

### Errors

Code   | Description
------ | -----------
-32099 | The global service is not available.
-32098 | The specified server does not exist.

### Result

This procedure returns no result.

## `warden.messageUser`

Sends a message to the specified user.

### Parameters

Index | Description
----- | -----------
0     | The source pseudoclient to send the message from.
1     | The target user to send the message to.
2+    | One or more messages to send.

### Errors

Code   | Description
------ | -----------
-32099 | The specified source does not exist.
-32098 | The specified target does not exist.

### Result

This procedure returns no result.

