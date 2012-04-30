package com.rackspace.papi.filter.routing;

import com.rackspace.papi.model.DestinationDomain;
import com.rackspace.papi.model.DestinationEndpoint;
import com.rackspace.papi.model.DomainNode;
import com.rackspace.papi.service.routing.RoutingService;
import javax.servlet.http.HttpServletRequest;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.BeforeClass;
import org.junit.experimental.runners.Enclosed;
import org.junit.runner.RunWith;
import static org.mockito.Mockito.*;

@RunWith(Enclosed.class)
public class DestinationLocationBuilderTest {

   public static class WhenConstructingBuilder {
      private RoutingService routingService;
      private DomainNode localhost;
      private DestinationEndpoint endpointDestination;
      private DestinationDomain domainDestination;
      private HttpServletRequest request;

      @Before
      public void setUp() {
         request = mock(HttpServletRequest.class);
         when(request.getScheme()).thenReturn("http");
         when(request.getLocalPort()).thenReturn(8080);
         
         routingService = mock(RoutingService.class);

         localhost = new DomainNode();
         
         localhost.setHttpPort(8080);
         localhost.setHttpsPort(0);
         localhost.setHostname("myhost");
         localhost.setId("local");
         
         endpointDestination = new DestinationEndpoint();
         domainDestination = new DestinationDomain();
      }
      
      @Test
      public void shouldContructAnEnpointBuilder() {
         DestinationLocationBuilder builder = new DestinationLocationBuilder(routingService, localhost, endpointDestination, "", request);
         assertTrue(builder.getBuilder() instanceof EndpointLocationBuilder);
      }

      @Test
      public void shouldContructADomainBuilder() {
         DestinationLocationBuilder builder = new DestinationLocationBuilder(routingService, localhost, domainDestination, "", request);
         assertTrue(builder.getBuilder() instanceof DomainLocationBuilder);
      }
      
      @Test(expected=IllegalArgumentException.class)
      public void shouldThrowIllegalArgumentForNullRouting() {
         new DestinationLocationBuilder(null, localhost, domainDestination, "", request);
      }
      
      @Test(expected=IllegalArgumentException.class)
      public void shouldThrowIllegalArgumentForNullHost() {
         new DestinationLocationBuilder(routingService, null, domainDestination, "", request);
      }
      
      @Test(expected=IllegalArgumentException.class)
      public void shouldThrowIllegalArgumentForNullDestination() {
         new DestinationLocationBuilder(routingService, localhost, null, "", request);
      }
      
   }
}