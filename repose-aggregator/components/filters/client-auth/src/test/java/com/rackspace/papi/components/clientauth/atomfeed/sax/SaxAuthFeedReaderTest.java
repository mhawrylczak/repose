package com.rackspace.papi.components.clientauth.atomfeed.sax;

import com.rackspace.papi.commons.util.http.ServiceClient;
import com.rackspace.papi.commons.util.http.ServiceClientResponse;
import com.rackspace.papi.components.clientauth.atomfeed.CacheKeys;
import com.rackspace.papi.service.serviceclient.akka.AkkaServiceClient;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.InputStream;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.mockito.Matchers.anyMap;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class SaxAuthFeedReaderTest {

    private ServiceClient client;
    private AkkaServiceClient akkaClient;
    private ServiceClientResponse resp1, resp2, resp3;
    private SaxAuthFeedReader reader;

    @Before
    public void setUp() throws FileNotFoundException {

        AppenderForTesting.clear();

        client = mock(ServiceClient.class);
        akkaClient = mock(AkkaServiceClient.class);

        InputStream fileReader1 = getClass().getResourceAsStream(File.separator + "META-INF" + File.separator + "feed.xml");
        InputStream fileReader2 = getClass().getResourceAsStream(File.separator + "META-INF" + File.separator + "empty-feed.xml");
        resp1 = new ServiceClientResponse(200, fileReader1);

        resp2 = new ServiceClientResponse(200, fileReader2);
        when(client.getPoolSize()).thenReturn(100);

    }

    @After
    public void tearDown() {
        AppenderForTesting.clear();
    }

    @Test
    public void shouldRetrieveUserAndTokenKeysFromAtomFeed() {

        when(client.get(eq("http://some.junit.test.feed/at/somepath"), anyMap())).thenReturn(resp1);
        when(client.get(eq("https://test.feed.atomhopper.rackspace.com/some/identity/feed/?marker=urn:uuid:b23a9c7f-5489-4fd8-bf10-3292032d805f&limit=25&search=&direction=forward"),
                anyMap())).thenReturn(resp2);
        reader = new SaxAuthFeedReader(client, akkaClient, "http://some.junit.test.feed/at/somepath", "atomId");
        CacheKeys keys = reader.getCacheKeys();

        String[] users = {"224277258"}; //User from atom feed
        String[] tokens = {"834d3be1-c479-11e2-8b8b-0800200c9a66"}; //token from atom feed

        assertArrayEquals("Retrieved key should have user from atom feed", keys.getUserKeys().toArray(), users);
        assertArrayEquals("Retrieved keys should have token from atom feed", keys.getTokenKeys().toArray(), tokens);
    }

    @Test
    public void shouldLogUnauthorizedFeeds() {

        resp3 = new ServiceClientResponse(401, null);
        when(client.get(eq("http://some.junit.test.feed/at/somepath"), anyMap())).thenReturn(resp3);
        reader = new SaxAuthFeedReader(client, akkaClient, "http://some.junit.test.feed/at/somepath", "atomId");
        CacheKeys keys = reader.getCacheKeys();

        assertEquals("Should log 401 with atom feed configured without auth", "Feed at http://some.junit.test.feed/at/somepath requires Authentication. Please "
                + "reconfigure Feed atomId with valid credentials and/or configure isAuthed to true", AppenderForTesting.getMessages()[0]);


    }

    @Test
    public void shouldLogServerErrorFromAtomFeeds() {

        resp3 = new ServiceClientResponse(503, null);
        when(client.get(eq("http://some.junit.test.feed/at/somepath"), anyMap())).thenReturn(resp3);
        reader = new SaxAuthFeedReader(client, akkaClient, "http://some.junit.test.feed/at/somepath", "atomId");

        CacheKeys keys = reader.getCacheKeys();

        assertEquals("Unable to retrieve atom feed from FeedatomId: http://some.junit.test.feed/at/somepath\n"
                + " Response Code: 503", AppenderForTesting.getMessages()[0]);
    }
}
