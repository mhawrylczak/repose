package features.filters.translation.httpx.processor.json.elements;

import features.filters.translation.httpx.processor.common.Element;
import org.xml.sax.ContentHandler;
import org.xml.sax.SAXException;

public class NullElement extends ScalarElement<String> implements Element {

   public NullElement(String element, String name, String value) {
      super(element, name, value);
   }

   @Override
   public void outputElement(ContentHandler handler) throws SAXException {
      handler.startElement(JSONX_URI, getLocalName(), getQname(), getAttributes());
      handler.endElement(JSONX_URI, getLocalName(), getQname());
   }
}
