using System;
using Blazored.LocalStorage;
using Microsoft.AspNetCore.Components.Authorization;
using System.Security.Claims;


namespace NewToBlazorWasm
{
    public class LocalStorageAuthenticationProvider : AuthenticationStateProvider
    {
        private readonly ILocalStorageService _localStorage;

        public LocalStorageAuthenticationProvider(ILocalStorageService localStorage)
        {
            this._localStorage = localStorage;
        }

        public override async Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            // retrieve user session from local storage
            var userSession = await _localStorage.GetItemAsync<string>("UserSessionKey");

            if (userSession != null)
            {
                // create authenticated user
                var identity = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.Name, userSession)
                }, "local_storage_auth");

                var user = new ClaimsPrincipal(identity);
                return new AuthenticationState(user);
            }
            else
            {
                // create anonymous user
                var anonymous = new ClaimsPrincipal(new ClaimsIdentity());
                return new AuthenticationState(anonymous);
            }
        }

        // Public method to update the state after a successful login
        public async Task UpdateAuthenticationState(string userSession)
        {
            ClaimsPrincipal claimsPrincipal;

            if (userSession != null)
            {
                // Store the session in local storage
                await _localStorage.SetItemAsync("UserSessionKey", userSession);
                // Build the user's identity from the token
                claimsPrincipal = new ClaimsPrincipal(
                    new ClaimsIdentity(
                        new[]{
                            new Claim(ClaimTypes.Name, userSession)
                        }
                    , "local_storage_auth"));
            }
            else
            {
                // Remove the session from local storage
                await _localStorage.RemoveItemAsync("UserSessionKey");
                // Create an anonymous user
                claimsPrincipal = new ClaimsPrincipal(new ClaimsIdentity());
            }

            // Notify the entire application that the authentication state has changed.
            // This causes <CascadingAuthenticationState> and <AuthorizeView> to re-render.
            NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(claimsPrincipal)));
        }

        // Helper method to mark user as logged out
        public async Task MarkUserAsLoggedOut()
        {
            await UpdateAuthenticationState(null);
        }

    }
}


