// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

namespace HighAvailability.Factories
{
    using HighAvailability.Interfaces;
    using Microsoft.Azure.Management.Media;
    using Microsoft.Azure.Services.AppAuthentication;
    using Microsoft.Extensions.Logging;
    using Microsoft.IdentityModel.Clients.ActiveDirectory;
    using Microsoft.Rest;
    using Microsoft.Rest.Azure.Authentication;
    using System;
    using System.Collections.Generic;
    using System.Net.Http;

    /// <summary>
    /// Factory class for creating IAzureMediaServicesClient instances
    /// </summary>
    public class MediaServiceInstanceFactory : IMediaServiceInstanceFactory
    {
        /// <summary>
        /// Configuration container to store data about media services instances
        /// </summary>
        private readonly IConfigService configService;

        /// <summary>
        /// Storage service to persist status of all calls to Media Services APIs
        /// </summary>
        private readonly IMediaServiceCallHistoryStorageService mediaServiceCallHistoryStorageService;

        /// <summary>
        /// List of Azure Media Client instances
        /// </summary>
        private IDictionary<string, IAzureMediaServicesClient> azureMediaServicesClientDictionary = new Dictionary<string, IAzureMediaServicesClient>();

        /// <summary>
        /// Object used to sync access to azureMediaServicesClient
        /// </summary>
        private object azureMediaServicesClientLockObject;

        /// <summary>
        /// flag to indicate that client reset is requested
        /// </summary>
        private bool resetRequested;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="mediaServiceCallHistoryStorageService">Service to store Media Services call history</param>
        /// <param name="configService">configuration container that stores data about Azure Media Service instances</param>
        public MediaServiceInstanceFactory(IMediaServiceCallHistoryStorageService mediaServiceCallHistoryStorageService, IConfigService configService)
        {
            this.mediaServiceCallHistoryStorageService = mediaServiceCallHistoryStorageService ?? throw new ArgumentNullException(nameof(mediaServiceCallHistoryStorageService));
            this.configService = configService ?? throw new ArgumentNullException(nameof(configService));
            this.azureMediaServicesClientLockObject = new object();
            this.resetRequested = false;
        }

        /// <summary>
        /// Returns instance of IAzureMediaServicesClient to connect to specific Azure Media Service instance.
        /// </summary>
        /// <param name="accountName">Azure Media Service account name</param>
        /// <param name="logger">Logger to log data</param>
        /// <returns>Created client</returns>
        public IAzureMediaServicesClient GetMediaServiceInstance(string accountName, ILogger logger)
        {
            if (!this.configService.MediaServiceInstanceConfiguration.ContainsKey(accountName))
            {
                throw new ArgumentException($"Invalid accountName {accountName}");
            }

            lock (this.azureMediaServicesClientLockObject)
            {
                if (this.azureMediaServicesClientDictionary.ContainsKey(accountName) && !this.resetRequested)
                {
                    return this.azureMediaServicesClientDictionary[accountName];
                }

                var settings = new ActiveDirectoryServiceSettings
                {
                    AuthenticationEndpoint = new Uri("https://login.windows-ppe.net/"),
                    TokenAudience = new Uri("https://management.core.windows.net/"),
                    ValidateAuthority = true
                };

                var credentials = ApplicationTokenProvider.LoginSilentAsync(
                    domain: "38bea1c0-7aaa-4e07-a418-edf29e6056a4",
                    credential: new ClientCredential(
                        this.configService.MediaServiceInstanceConfiguration[accountName].AADApplicationId,
                        this.configService.MediaServiceInstanceConfiguration[accountName].AADApplicationSecret),
                    settings: settings).GetAwaiter().GetResult();

                // Establish a connection to Media Services.
                this.azureMediaServicesClientDictionary[accountName] = new AzureMediaServicesClient(new Uri("https://api-dogfood.resources.windows-int.net/"), credentials,
                    new DelegatingHandler[] { new CallHistoryHandler(this.mediaServiceCallHistoryStorageService, this, logger) })
                {
                    SubscriptionId = this.configService.MediaServiceInstanceConfiguration[accountName].SubscriptionId
                };

                this.resetRequested = false;

                return this.azureMediaServicesClientDictionary[accountName];
            }
        }

        /// <summary>
        /// Resets Media Service client. This should be used when error happens and new client connection is required.
        /// </summary>
        /// <returns>Async operation result</returns>
        public void ResetMediaServiceInstance()
        {
            lock (this.azureMediaServicesClientLockObject)
            {
                // this will force to recreate client on next call
                this.resetRequested = true;
            }
        }
    }
}
