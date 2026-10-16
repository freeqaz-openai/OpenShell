### Installation exchange and accepted response custody

A managed supervisor creates one configuration instance ID and an Ed25519 key
for its process lifetime. Only the public key enters its authenticated hello.
After the gateway accepts that session, the supervisor schedules rotation of
the token it used for startup discovery. The new token binds the enrolled key
and the same configuration instance. Discovery, a bearer, or a public ID
alone cannot open a protected operation.

For protected HTTPS, the supervisor holds the accepted workload stream before
reading the request. It signs the authority’s challenge and the exact resolve
request, including a fresh commitment to that stream. Resolve, authorization
and the complete bounded response (including final trailers) use one
bidirectional exchange. The supervisor checks that the committed send permit
names its custody, sends at most once, and releases only a complete approved
response on the stream it still holds. A failed or uncertain send is terminal.

A fresh policy may explicitly grant execution-wide authority to processes
inside the workload. This profile requires provenance from a verified blocked
workload connect and signs the hash of the admitted typed policy. An existing
executable-pin grant still requires its exact verified leaf. A missing profile,
mixed grant, unavailable enrollment or ambiguous response fails closed.

Content-free supervisor events correlate these transitions by request ID.
A local `no_permit` means the supplier accepted no usable send permit; the
authority’s durable transaction and an independent origin observation are
needed to determine whether the authority committed or a provider saw traffic.
