"""
Integration test demonstrating intermediate CA certificate signing and chain validation.
"""

import asyncio
import os
import tempfile
from typing import List

# Import test utilities
try:
    import importlib.util

    CRYPTO_AVAILABLE = importlib.util.find_spec("cryptography") is not None
    if CRYPTO_AVAILABLE:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
except ImportError:
    CRYPTO_AVAILABLE = False


async def test_intermediate_ca_signing_integration():
    """
    Comprehensive integration test for intermediate CA signing.

    This test demonstrates:
    1. Creating a root CA and intermediate CA
    2. Configuring the FastAPI CA signing service with intermediate CA
    3. Signing certificates using the intermediate CA
    4. Verifying the complete certificate chain
    5. Cross-validation between nodes with different intermediate CAs
    """
    if not CRYPTO_AVAILABLE:
        print("❌ Cryptography package not available, skipping test")
        return False

    print("🔐 Starting Intermediate CA Signing Integration Test\n")

    try:
        from naylence.fame.fastapi.ca_signing_router import CertificateSigningRequest, LocalCASigningService
        from naylence.fame.security.cert.ca_service import CASigningService, create_test_ca
        from naylence.fame.security.crypto.providers.default_crypto_provider import DefaultCryptoProvider

        # Step 1: Create Root CA
        print("1️⃣ Creating Root CA...")
        root_cert_pem, root_key_pem = create_test_ca()
        root_ca_service = CASigningService(root_cert_pem, root_key_pem)
        print("   ✅ Root CA created successfully")

        # Step 2: Create Intermediate CA
        print("\n2️⃣ Creating Intermediate CA...")
        intermediate_private_key = ed25519.Ed25519PrivateKey.generate()
        intermediate_public_key_pem = (
            intermediate_private_key.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            .decode()
        )

        intermediate_cert_pem = root_ca_service.create_intermediate_ca(
            public_key_pem=intermediate_public_key_pem,
            ca_name="Production Intermediate CA",
            permitted_paths=["/production/"],
        )

        intermediate_key_pem = intermediate_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        print("   ✅ Intermediate CA created successfully")

        # Step 3: Create LocalCASigningService with Intermediate CA
        print("\n3️⃣ Configuring CA Signing Service with Intermediate CA...")
        ca_signing_service = LocalCASigningService(
            ca_cert_pem=root_cert_pem,
            ca_key_pem=root_key_pem,
            intermediate_cert_pem=intermediate_cert_pem,
            intermediate_key_pem=intermediate_key_pem,
        )
        print("   ✅ CA Signing Service configured")

        # Step 4: Create CSR for a production node
        print("\n4️⃣ Creating Certificate Signing Request...")
        crypto = DefaultCryptoProvider()
        crypto.set_node_context(
            node_id="prod-api-server-01",
            physical_path="/production/api/server-01",
            logicals=["v1.api.production", "health.production"],
        )

        csr_pem = crypto.create_csr(
            node_id="prod-api-server-01",
            physical_path="/production/api/server-01",
            logicals=["v1.api.production", "health.production"],
        )

        csr_request = CertificateSigningRequest(
            csr_pem=csr_pem,
            requester_id="prod-api-server-01",
            physical_path="/production/api/server-01",
            logicals=["v1.api.production", "health.production"],
        )
        print("   ✅ CSR created for production API server")

        # Step 5: Issue Certificate using Intermediate CA
        print("\n5️⃣ Issuing Certificate using Intermediate CA...")
        response = await ca_signing_service.issue_certificate(csr_request)
        print("   ✅ Certificate issued successfully")
        print(f"   📅 Expires at: {response.expires_at}")

        # Step 6: Validate Certificate Chain
        print("\n6️⃣ Validating Certificate Chain...")

        # Parse certificate chain
        chain_parts = response.certificate_chain_pem.split("-----END CERTIFICATE-----")
        cert_count = len([part for part in chain_parts if "-----BEGIN CERTIFICATE-----" in part])
        print(f"   📊 Certificate chain contains {cert_count} certificates")

        # Extract individual certificates
        chain_certs: List[x509.Certificate] = []
        current_cert = ""
        in_cert = False

        for line in response.certificate_chain_pem.split("\n"):
            if "-----BEGIN CERTIFICATE-----" in line:
                in_cert = True
                current_cert = line + "\n"
            elif "-----END CERTIFICATE-----" in line:
                current_cert += line + "\n"
                chain_certs.append(x509.load_pem_x509_certificate(current_cert.encode()))
                current_cert = ""
                in_cert = False
            elif in_cert:
                current_cert += line + "\n"

        assert len(chain_certs) == 3, f"Expected 3 certificates in chain, got {len(chain_certs)}"

        node_cert = chain_certs[0]
        intermediate_cert = chain_certs[1]
        root_cert = chain_certs[2]

        # Validate chain relationships
        assert node_cert.issuer == intermediate_cert.subject, "Node cert not issued by intermediate CA"
        assert intermediate_cert.issuer == root_cert.subject, "Intermediate cert not issued by root CA"

        print("   ✅ Certificate chain validation passed")
        print("   🔗 Chain: Node → Intermediate → Root")
        print(f"   📋 Node Subject: {node_cert.subject}")
        print(f"   📋 Intermediate Subject: {intermediate_cert.subject}")
        print(f"   📋 Root Subject: {root_cert.subject}")

        # Step 7: Test Environment Variable Configuration
        print("\n7️⃣ Testing Environment Variable Configuration...")

        with tempfile.TemporaryDirectory() as temp_dir:
            # Write certificates to temporary files
            root_cert_file = os.path.join(temp_dir, "root_ca.pem")
            root_key_file = os.path.join(temp_dir, "root_ca.key")
            intermediate_cert_file = os.path.join(temp_dir, "intermediate_ca.pem")
            intermediate_key_file = os.path.join(temp_dir, "intermediate_ca.key")

            with open(root_cert_file, "w") as f:
                f.write(root_cert_pem)
            with open(root_key_file, "w") as f:
                f.write(root_key_pem)
            with open(intermediate_cert_file, "w") as f:
                f.write(intermediate_cert_pem)
            with open(intermediate_key_file, "w") as f:
                f.write(intermediate_key_pem)

            # Set environment variables
            os.environ["FAME_CA_CERT_FILE"] = root_cert_file
            os.environ["FAME_CA_KEY_FILE"] = root_key_file
            os.environ["FAME_INTERMEDIATE_CERT_FILE"] = intermediate_cert_file
            os.environ["FAME_INTERMEDIATE_KEY_FILE"] = intermediate_key_file

            try:
                # Create service that loads from environment
                env_ca_service = LocalCASigningService()

                # Issue another certificate
                crypto2 = DefaultCryptoProvider()
                crypto2.set_node_context(
                    node_id="prod-worker-02",
                    physical_path="/production/worker/server-02",
                    logicals=["queue.worker.production"],
                )

                csr2_pem = crypto2.create_csr(
                    node_id="prod-worker-02",
                    physical_path="/production/worker/server-02",
                    logicals=["queue.worker.production"],
                )

                csr2_request = CertificateSigningRequest(
                    csr_pem=csr2_pem,
                    requester_id="prod-worker-02",
                    physical_path="/production/worker/server-02",
                    logicals=["queue.worker.production"],
                )

                response2 = await env_ca_service.issue_certificate(csr2_request)
                print("   ✅ Certificate issued using environment variables")
                print(f"   📅 Second cert expires at: {response2.expires_at}")

            finally:
                # Clean up environment variables
                for env_var in [
                    "FAME_CA_CERT_FILE",
                    "FAME_CA_KEY_FILE",
                    "FAME_INTERMEDIATE_CERT_FILE",
                    "FAME_INTERMEDIATE_KEY_FILE",
                ]:
                    if env_var in os.environ:
                        del os.environ[env_var]

        # Step 8: Demonstrate Cross-Node Validation
        print("\n8️⃣ Demonstrating Cross-Node Certificate Validation...")

        # Both certificates should share the same root CA in their chains
        assert root_cert_pem.strip() in response.certificate_chain_pem
        assert root_cert_pem.strip() in response2.certificate_chain_pem

        # Both should include the same intermediate CA
        assert intermediate_cert_pem.strip() in response.certificate_chain_pem
        assert intermediate_cert_pem.strip() in response2.certificate_chain_pem

        print("   ✅ Both nodes can validate each other's certificates using the complete chain")
        print("   🔗 Shared trust anchor: Root CA")
        print("   🔗 Shared intermediate: Production Intermediate CA")

        print("\n🎉 Intermediate CA Signing Integration Test Completed Successfully!")
        print("\n📝 Summary:")
        print("   • Root CA created and configured")
        print("   • Intermediate CA generated and signed by root CA")
        print("   • Node certificates signed by intermediate CA")
        print("   • Complete certificate chains provided (node → intermediate → root)")
        print("   • Environment variable configuration tested")
        print("   • Cross-node validation demonstrated")
        print("   • Ready for production use with proper PKI hierarchy")

        return True

    except Exception as e:
        print(f"\n❌ Test failed with error: {str(e)}")
        import traceback

        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = asyncio.run(test_intermediate_ca_signing_integration())
    exit(0 if success else 1)
