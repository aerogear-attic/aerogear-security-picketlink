/**
 * JBoss, Home of Professional Open Source
 * Copyright Red Hat, Inc., and individual contributors
 * by the @authors tag. See the copyright.txt in the distribution for a
 * full listing of individual contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jboss.aerogear.controller.demo;

import org.jboss.aerogear.controller.demo.model.AeroGearUser;
import org.jboss.aerogear.controller.router.AbstractRoutingModule;
import org.jboss.aerogear.controller.router.RequestMethod;

/**
 * Routes are the core of aerogear-controller–demo.
 * It's where we bind the the application business controller {@link Home}
 * to the URL it responds.<br>
 * All the configuration is done with a type safe DSL.
 *
 * @see Home
 */

public class Routes extends AbstractRoutingModule {

    /**
     * Entry point for configuring the routes mapping http requests to the pojo controllers
     */
    @Override
    public void configuration() throws Exception {

        route()
                .from("/")
                .on(RequestMethod.GET)
                .to(Home.class).index();

        route()
                .from("/login")
                .on(RequestMethod.GET)
                .to(Login.class).index();
        route()
                .from("/login")
                .on(RequestMethod.POST)
                .to(Login.class).login(param(AeroGearUser.class));

    }
}
