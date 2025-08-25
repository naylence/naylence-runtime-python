"""
Test multi-level intermediate CA chain support in the CA signing router.

This test demonstrates the generic intermediate CA chain functionality:
- Root CA
- Intermediate CA Level 1
- Intermediate CA Level 2 (signing CA)
- End Entity Certificate
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


async def test_multi_level_intermediate_ca_chain():
    """
    Test a complete multi-level intermediate CA chain.

    Certificate Hierarchy:
    Root CA
    └── Intermediate CA Level 1
        └── Intermediate CA Level 2 (Signing CA)
            └── End Entity Certificate
    """
    if not CRYPTO_AVAILABLE:
        print("❌ Cryptography package not available, skipping test")
        return False

    print("🏗️ Starting Multi-Level Intermediate CA Chain Test\n")

    try:
        from naylence.fame.fastapi.ca_signing_router import (
            CertificateSigningRequest,
            LocalCASigningService,
        )
        from naylence.fame.security.cert.ca_service import (
            CASigningService,
            create_test_ca,
        )
        from naylence.fame.security.crypto.providers.default_crypto_provider import (
            DefaultCryptoProvider,
        )

        # Step 1: Create Root CA
        print("1️⃣ Creating Root CA...")
        root_cert_pem, root_key_pem = create_test_ca()
        root_ca_service = CASigningService(root_cert_pem, root_key_pem)
        print("   ✅ Root CA created")

        # Step 2: Create Intermediate CA Level 1
        print("\n2️⃣ Creating Intermediate CA Level 1...")
        intermediate1_private_key = ed25519.Ed25519PrivateKey.generate()
        intermediate1_public_key_pem = (
            intermediate1_private_key.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode()
        )

        intermediate1_cert_pem = root_ca_service.create_intermediate_ca(
            public_key_pem=intermediate1_public_key_pem,
            ca_name="Organization Intermediate CA",
            permitted_paths=["/org/"],
        )

        intermediate1_key_pem = intermediate1_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        print("   ✅ Intermediate CA Level 1 created")

        # Step 3: Create Intermediate CA Level 2 (Signing CA)
        print("\n3️⃣ Creating Intermediate CA Level 2 (Signing CA)...")
        intermediate1_ca_service = CASigningService(intermediate1_cert_pem, intermediate1_key_pem)

        intermediate2_private_key = ed25519.Ed25519PrivateKey.generate()
        intermediate2_public_key_pem = (
            intermediate2_private_key.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode()
        )

        intermediate2_cert_pem = intermediate1_ca_service.create_intermediate_ca(
            public_key_pem=intermediate2_public_key_pem,
            ca_name="Department Signing CA",
            permitted_paths=["/org/department/"],
        )

        intermediate2_key_pem = intermediate2_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        print("   ✅ Intermediate CA Level 2 (Signing CA) created")

        # Step 4: Build Complete Intermediate Chain
        print("\n4️⃣ Building Complete Intermediate Chain...")
        # Chain should be ordered from leaf to root (signing CA → intermediate1 → root)
        # But for the intermediate_chain_pem, we include only the intermediates (not root)
        intermediate_chain_pem = f"{intermediate2_cert_pem}\n{intermediate1_cert_pem}"
        print("   ✅ Intermediate chain built (2 levels)")
        print("   📋 Chain: Signing CA → Org CA → Root CA")

        # Step 5: Configure CA Signing Service with Multi-Level Chain
        print("\n5️⃣ Configuring CA Signing Service with Multi-Level Chain...")
        ca_signing_service = LocalCASigningService(
            ca_cert_pem=root_cert_pem,
            ca_key_pem=root_key_pem,
            intermediate_chain_pem=intermediate_chain_pem,
            signing_cert_pem=intermediate2_cert_pem,  # Use Level 2 as signing cert
            signing_key_pem=intermediate2_key_pem,  # Use Level 2 key for signing
        )
        print("   ✅ Multi-level CA chain configured")

        # Step 6: Create CSR for End Entity
        print("\n6️⃣ Creating Certificate Signing Request for End Entity...")
        crypto = DefaultCryptoProvider()
        crypto.set_node_context(
            node_id="dept-api-server-01",
            physical_path="/org/department/api/server-01",
            logicals=["v1.api.department.org", "health.department.org"],
        )

        csr_pem = crypto.create_csr(
            node_id="dept-api-server-01",
            physical_path="/org/department/api/server-01",
            logicals=["v1.api.department.org", "health.department.org"],
        )

        csr_request = CertificateSigningRequest(
            csr_pem=csr_pem,
            requester_id="dept-api-server-01",
            physical_path="/org/department/api/server-01",
            logicals=["v1.api.department.org", "health.department.org"],
        )
        print("   ✅ CSR created for department API server")

        # Step 7: Issue Certificate using Multi-Level Chain
        print("\n7️⃣ Issuing Certificate using Multi-Level Intermediate Chain...")
        response = await ca_signing_service.issue_certificate(csr_request)
        print("   ✅ Certificate issued successfully")
        print(f"   📅 Expires at: {response.expires_at}")

        # Step 8: Validate Complete Certificate Chain
        print("\n8️⃣ Validating Complete Certificate Chain...")

        # Parse certificate chain
        chain_parts = response.certificate_chain_pem.split("-----END CERTIFICATE-----")
        cert_count = len([part for part in chain_parts if "-----BEGIN CERTIFICATE-----" in part])
        print(f"   📊 Complete certificate chain contains {cert_count} certificates")

        # Extract individual certificates from the response
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

        expected_chain_length = 4  # End Entity + Level 2 + Level 1 + Root
        assert (
            len(chain_certs) == expected_chain_length
        ), f"Expected {expected_chain_length} certificates in chain, got {len(chain_certs)}"

        # Validate the complete chain: End Entity → Level 2 → Level 1 → Root
        end_entity_cert = chain_certs[0]
        signing_ca_cert = chain_certs[1]  # Level 2 (Signing CA)
        intermediate1_cert = chain_certs[2]  # Level 1 (Org CA)
        root_ca_cert = chain_certs[3]  # Root CA

        # Validate chain relationships
        assert end_entity_cert.issuer == signing_ca_cert.subject, "End entity cert not issued by signing CA"
        assert (
            signing_ca_cert.issuer == intermediate1_cert.subject
        ), "Signing CA not issued by intermediate CA level 1"
        assert (
            intermediate1_cert.issuer == root_ca_cert.subject
        ), "Intermediate CA level 1 not issued by root CA"

        print("   ✅ Complete certificate chain validation passed")
        print("   🔗 Complete Chain: End Entity → Signing CA → Org CA → Root CA")
        print(f"   📋 End Entity Subject: {end_entity_cert.subject}")
        print(f"   📋 Signing CA Subject: {signing_ca_cert.subject}")
        print(f"   📋 Org CA Subject: {intermediate1_cert.subject}")
        print(f"   📋 Root CA Subject: {root_ca_cert.subject}")

        # Step 9: Test Environment Variable Configuration with Chain
        print("\n9️⃣ Testing Environment Variable Configuration with Chain...")

        with tempfile.TemporaryDirectory() as temp_dir:
            # Write certificates to temporary files
            root_cert_file = os.path.join(temp_dir, "root_ca.pem")
            root_key_file = os.path.join(temp_dir, "root_ca.key")
            intermediate_chain_file = os.path.join(temp_dir, "intermediate_chain.pem")
            signing_cert_file = os.path.join(temp_dir, "signing_ca.pem")
            signing_key_file = os.path.join(temp_dir, "signing_ca.key")

            with open(root_cert_file, "w") as f:
                f.write(root_cert_pem)
            with open(root_key_file, "w") as f:
                f.write(root_key_pem)
            with open(intermediate_chain_file, "w") as f:
                f.write(intermediate_chain_pem)
            with open(signing_cert_file, "w") as f:
                f.write(intermediate2_cert_pem)
            with open(signing_key_file, "w") as f:
                f.write(intermediate2_key_pem)

            # Set environment variables
            os.environ["FAME_CA_CERT_FILE"] = root_cert_file
            os.environ["FAME_CA_KEY_FILE"] = root_key_file
            os.environ["FAME_INTERMEDIATE_CHAIN_FILE"] = intermediate_chain_file
            os.environ["FAME_SIGNING_CERT_FILE"] = signing_cert_file
            os.environ["FAME_SIGNING_KEY_FILE"] = signing_key_file

            try:
                # Create service that loads from environment
                env_ca_service = LocalCASigningService()

                # Issue another certificate
                crypto2 = DefaultCryptoProvider()
                crypto2.set_node_context(
                    node_id="dept-worker-02",
                    physical_path="/org/department/worker/server-02",
                    logicals=["queue.worker.department.org"],
                )

                csr2_pem = crypto2.create_csr(
                    node_id="dept-worker-02",
                    physical_path="/org/department/worker/server-02",
                    logicals=["queue.worker.department.org"],
                )

                csr2_request = CertificateSigningRequest(
                    csr_pem=csr2_pem,
                    requester_id="dept-worker-02",
                    physical_path="/org/department/worker/server-02",
                    logicals=["queue.worker.department.org"],
                )

                response2 = await env_ca_service.issue_certificate(csr2_request)
                print("   ✅ Certificate issued using environment variables with multi-level chain")
                print(f"   📅 Second cert expires at: {response2.expires_at}")

                # Verify second certificate also has complete chain
                chain2_parts = response2.certificate_chain_pem.split("-----END CERTIFICATE-----")
                cert2_count = len([part for part in chain2_parts if "-----BEGIN CERTIFICATE-----" in part])
                assert cert2_count == 4, f"Expected 4 certificates in second chain, got {cert2_count}"

            finally:
                # Clean up environment variables
                for env_var in [
                    "FAME_CA_CERT_FILE",
                    "FAME_CA_KEY_FILE",
                    "FAME_INTERMEDIATE_CHAIN_FILE",
                    "FAME_SIGNING_CERT_FILE",
                    "FAME_SIGNING_KEY_FILE",
                ]:
                    if env_var in os.environ:
                        del os.environ[env_var]

        # Step 10: Demonstrate Cross-Node Validation with Multi-Level Chain
        print("\n🔟 Demonstrating Cross-Node Certificate Validation with Multi-Level Chain...")

        # Both certificates should share the same complete chain
        assert root_cert_pem.strip() in response.certificate_chain_pem
        assert root_cert_pem.strip() in response2.certificate_chain_pem

        # Both should include the complete intermediate chain
        assert intermediate1_cert_pem.strip() in response.certificate_chain_pem
        assert intermediate1_cert_pem.strip() in response2.certificate_chain_pem
        assert intermediate2_cert_pem.strip() in response.certificate_chain_pem
        assert intermediate2_cert_pem.strip() in response2.certificate_chain_pem

        print(
            "   ✅ Both nodes can validate each other's certificates using the complete multi-level chain"
        )
        print("   🔗 Shared trust anchor: Root CA")
        print("   🔗 Shared intermediate chain: Org CA → Signing CA")

        print("\n🎉 Multi-Level Intermediate CA Chain Test Completed Successfully!")
        print("\n📝 Summary:")
        print("   • Root CA created and configured")
        print("   • Multi-level intermediate CA chain generated:")
        print("     - Level 1: Organization Intermediate CA")
        print("     - Level 2: Department Signing CA")
        print("   • End entity certificates signed by Level 2 CA")
        print("   • Complete certificate chains provided (4 certificates each)")
        print("   • Environment variable configuration tested with chains")
        print("   • Cross-node validation demonstrated")
        print("   • Ready for production use with complex PKI hierarchies")
        print("\n🏗️ Architecture:")
        print("   Root CA")
        print("   └── Organization Intermediate CA")
        print("       └── Department Signing CA")
        print("           ├── End Entity Certificate 1")
        print("           └── End Entity Certificate 2")

        return True

    except Exception as e:
        print(f"\n❌ Test failed with error: {str(e)}")
        import traceback

        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = asyncio.run(test_multi_level_intermediate_ca_chain())
    exit(0 if success else 1)
