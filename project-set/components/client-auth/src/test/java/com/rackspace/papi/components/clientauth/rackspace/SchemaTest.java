package com.rackspace.papi.components.clientauth.rackspace;

import com.rackspace.papi.components.clientauth.config.ClientAuthConfig;
import javax.xml.XMLConstants;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.Unmarshaller;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.SchemaFactory;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.runners.Enclosed;
import org.junit.runner.RunWith;

import static org.junit.Assert.*;

/**
 *
 * @author jhopper
 */
@RunWith(Enclosed.class)
public class SchemaTest {

    public static final SchemaFactory SCHEMA_FACTORY = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);

    public static class WhenValidating {

        private JAXBContext jaxbContext;
        private Unmarshaller jaxbUnmarshaller;

        @Before
        public void standUp() throws Exception {
            jaxbContext = JAXBContext.newInstance(
                    com.rackspace.papi.components.clientauth.config.ObjectFactory.class,
                    com.rackspace.papi.components.clientauth.basic.config.ObjectFactory.class,
                    com.rackspace.papi.components.clientauth.rackspace.config.ObjectFactory.class);

            jaxbUnmarshaller = jaxbContext.createUnmarshaller();

            jaxbUnmarshaller.setSchema(SCHEMA_FACTORY.newSchema(
                    new StreamSource[]{
                        new StreamSource(SchemaTest.class.getResourceAsStream("/META-INF/schema/client-auth/rackspace-auth-v1.1/rackspace-auth-v1.1.xsd")),
                        new StreamSource(SchemaTest.class.getResourceAsStream("/META-INF/schema/client-auth/http-basic/http-basic.xsd")),
                        new StreamSource(SchemaTest.class.getResourceAsStream("/META-INF/schema/client-auth/auth.xsd"))
                    }));
        }

        @Test
        public void shouldValidateAgainstStaticExample() throws Exception {
            final StreamSource sampleSource = new StreamSource(SchemaTest.class.getResourceAsStream("/META-INF/xsd/client-auth-n.cfg.xml"));

            assertNotNull("Expected element should not be null", jaxbUnmarshaller.unmarshal(sampleSource, ClientAuthConfig.class).getValue().getRackspaceAuth());
        }
    }
}
