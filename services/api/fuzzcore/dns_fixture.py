"""Local UDP DNS fixture, not a recursive resolver. Never contacts upstream DNS."""
import socketserver
import dns.message
import dns.rcode
import dns.rdatatype
import dns.rdataclass
import dns.rrset


def server(address=('0.0.0.0',5353),wildcard=False):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            wire,sock=self.request
            if len(wire)>512:return
            try:
                query=dns.message.from_wire(wire)
                response=dns.message.make_response(query)
                valid=len(query.question)==1
                question=query.question[0] if valid else None
                name=str(question.name).lower() if valid else ''
                valid=valid and question.rdtype==dns.rdatatype.A and question.rdclass==dns.rdataclass.IN and (name=='lab.invalid.' or name.endswith('.lab.invalid.'))
                if valid and (name=='app.lab.invalid.' or wildcard):
                    response.answer.append(dns.rrset.from_text(name,30,'IN','A','192.0.2.10'))
                else:response.set_rcode(dns.rcode.NXDOMAIN)
                sock.sendto(response.to_wire(max_size=512),self.client_address)
            except Exception:return
    return socketserver.UDPServer(address,Handler)


if __name__=='__main__':
    with server() as fixture:fixture.serve_forever()
