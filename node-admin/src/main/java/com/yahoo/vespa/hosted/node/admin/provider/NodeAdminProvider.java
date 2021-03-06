// Copyright 2017 Yahoo Holdings. Licensed under the terms of the Apache 2.0 license. See LICENSE in the project root.
package com.yahoo.vespa.hosted.node.admin.provider;

import com.google.inject.Inject;
import com.yahoo.concurrent.classlock.ClassLocking;
import com.yahoo.container.di.componentgraph.Provider;
import com.yahoo.vespa.athenz.identity.SiaIdentityProvider;
import com.yahoo.vespa.hosted.dockerapi.Docker;
import com.yahoo.vespa.hosted.dockerapi.metrics.MetricReceiverWrapper;
import com.yahoo.vespa.hosted.node.admin.component.ConfigServerInfo;
import com.yahoo.vespa.hosted.node.admin.component.DockerAdminComponent;
import com.yahoo.vespa.hosted.node.admin.config.ConfigServerConfig;
import com.yahoo.vespa.hosted.node.admin.configserver.ConfigServerApi;
import com.yahoo.vespa.hosted.node.admin.configserver.ConfigServerApiImpl;
import com.yahoo.vespa.hosted.node.admin.configserver.ConfigServerClients;
import com.yahoo.vespa.hosted.node.admin.configserver.RealConfigServerClients;

public class NodeAdminProvider implements Provider<NodeAdminStateUpdater> {
    private final DockerAdminComponent dockerAdmin;

    @Inject
    public NodeAdminProvider(ConfigServerConfig configServerConfig,
                             SiaIdentityProvider identityProvider,
                             Docker docker,
                             MetricReceiverWrapper metricReceiver,
                             ClassLocking classLocking) {
        ConfigServerInfo configServerInfo = new ConfigServerInfo(configServerConfig);
        ConfigServerApi configServerApi = ConfigServerApiImpl.create(configServerInfo, identityProvider);
        ConfigServerClients clients = new RealConfigServerClients(configServerApi);

        dockerAdmin = new DockerAdminComponent(configServerConfig,
                identityProvider,
                docker,
                metricReceiver,
                classLocking,
                clients);
        dockerAdmin.enable();
    }

    @Override
    public NodeAdminStateUpdater get() {
        return dockerAdmin.getNodeAdminStateUpdater();
    }

    @Override
    public void deconstruct() {
        dockerAdmin.disable();
    }
}
