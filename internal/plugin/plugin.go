package plugin

import sdk "ads-httpproxy/pkg/plugin"

// Aliases preserve compatibility with existing plugins while exposing the SDK
// to plugins developed outside this repository.
type Context = sdk.Context
type Plugin = sdk.Plugin
