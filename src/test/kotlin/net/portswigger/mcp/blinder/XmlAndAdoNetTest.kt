package net.portswigger.mcp.blinder

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * wave-12: (A) XML element secrets `<password>..</password>` (incl. namespaced `<wsse:Password>` and
 * CDATA), and (B) ADO.NET/ODBC `Key=Value;` connection strings (`Pwd=`/`Password=`). Value only is
 * masked; tags/keys/structure preserved; byte-exact round-trip; sensitive-key whitelist reused.
 */
class XmlAndAdoNetTest {

    private fun mask(text: String) = Masker(Vault()).mask(text)

    @Test
    fun `xml element secrets are masked`() {
        assertTrue(mask("<password>Xml0P4ssw0rd</password>").contains("<password>{{SECRET_1}}</password>"))
        assertTrue(mask("<wsse:Password>SoapPw123</wsse:Password>").contains("<wsse:Password>{{SECRET_1}}</wsse:Password>"))
        val attr = mask("""<apiKey id="1">ak_live_xyz</apiKey>""")
        assertFalse(attr.contains("ak_live_xyz"), attr)
        assertTrue(attr.contains("""<apiKey id="1">{{APIKEY_1}}</apiKey>"""), attr)
    }

    @Test
    fun `xml cdata secret is masked, structure preserved`() {
        val out = mask("<client_secret><![CDATA[cs_abc!@#]]></client_secret>")
        assertFalse(out.contains("cs_abc!@#"), out)
        assertTrue(out.contains("<client_secret><![CDATA[{{SECRET_1}}]]></client_secret>"), out)
    }

    @Test
    fun `non-sensitive xml elements are not masked`() {
        val out = mask("<user><name>myapp</name><title>Hello</title></user>")
        assertEquals("<user><name>myapp</name><title>Hello</title></user>", out)
    }

    @Test
    fun `ado_net connection string password is masked, other keys preserved`() {
        val out = mask("Data Source=dbhost;Uid=sa;Pwd=SaXmlPass123;Encrypt=true")
        assertFalse(out.contains("SaXmlPass123"), out)
        assertTrue(out.contains("Pwd={{SECRET_1}};"), out)
        assertTrue(out.contains("Data Source=dbhost"), out)
        assertTrue(out.contains("Uid=sa"), out)
        assertTrue(out.contains("Encrypt=true"), out)

        val out2 = mask("Server=srv;Password=DbPw99;")
        assertTrue(out2.contains("Password={{SECRET_1}};"), out2)
        assertTrue(out2.contains("Server=srv"), out2)
    }

    @Test
    fun `xml and connection string round-trip exactly`() {
        val vault = Vault()
        val masker = Masker(vault)
        val rehydrator = Rehydrator(vault)
        val real = "<wsse:Password>SoapPw123</wsse:Password> conn=Server=srv;Pwd=SaXmlPass123;"
        val masked = masker.mask(real)
        assertFalse(masked.contains("SoapPw123"), masked)
        assertFalse(masked.contains("SaXmlPass123"), masked)
        assertEquals(real, rehydrator.rehydrate(masked).text)
    }
}
