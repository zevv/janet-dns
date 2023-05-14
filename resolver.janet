
# Two way mapping of DNS query types to their numeric values
(def- qtype {
    :A 1 :NS 2 :CNAME 5 :SOA 6 :PTR 12 :MX 15 :TXT 16 :AAAA 28 :SRV 33 :OPT 41 :AXFR 252 :ANY 255
    1 :A 2 :NS 5 :CNAME 6 :SOA 12 :PTR 15 :MX 16 :TXT 28 :AAAA 33 :SRV 41 :OPT 252 :AXFR 255 :ANY})

(varfn decode-name [buf off parts] 0)

# Encoding

(defn- pack [buf & kvs]
  (each [k v] (partition 2 kvs)
    (match k
      :u8 (buffer/push-byte buf v)
      :u16 (pack buf :u8 (brshift v 8) :u8 (band v 0xff))
      :string (buffer/push buf v)
      :name (do (each part (string/split "." v)
                (pack buf :u8 (length part) :string part))
              (pack buf :u8 0))
      )))

(defn- dns-encode [pkt]
  (def buf @"")
  (pack buf :u16 (pkt :id)
            :u16 0x0100 # flags
            :u16 (length (pkt :questions))
            :u16 (length (pkt :answers))
            :u16 0  # authority RRs
            :u16 0) # additional RRs
  (each q (pkt :questions)
    (pack buf :name (q :name)
              :u16 (qtype (q :type))
              :u16 0x0001)) # IN class
  buf)

# Unpacking of binary data

(defn- unpack-at [buf off & ks]
  (var off off)
  (def result @[])
  (each k ks
    (def [off-next v]
      (match k
        :name (let [parts @[] off (decode-name buf off parts)]
                  [off (string/join parts ".")])
        :u8 [(inc off) (get buf off)]
        :u16 (let [[off v1 v2] (unpack-at buf off :u8 :u8)]
               [off (+ (blshift v1 8) v2)])
        :u32 (let [[off v1 v2] (unpack-at buf off :u16 :u16)]
               [off (+ (blshift v1 16) v2)])
        n [(+ off n) (slice buf off (+ off n))]
        ))
    (set off off-next)
    (array/push result v))
  [off ;result])

# Little unpack helper to keep track of buffer and offset

(defn- unpacker [buf]
  (var off 0)
  (fn [& ks]
    (def [off-next & vs] (unpack-at buf off ;ks))
    (set off off-next)
    vs))

# Decode a DNS name, which is a sequence of labels, each of which is a length,
# also handling name compression.
 
(defn- decode-part-label [buf off len parts]
  (def off-next (+ off len))
  (array/push parts (slice buf off off-next))
  (decode-name buf off-next parts))

(defn- decode-part-compressed [buf off len parts]
  (def [off ptr] (unpack-at buf off :u8))
  (decode-name buf ptr parts)
  off)

(defn- is-compressed? [len]
  (= 0xc0 (band 0xc0 len)))

(varfn decode-name [buf off parts]
  (def [off len] (unpack-at buf off :u8))
  (if (> len 0)
    (if (is-compressed? len)
      (decode-part-compressed buf off len parts)
      (decode-part-label buf off len parts))
    off))

# Decode payload data depending on the type of the question or answer

(defn- decode-data [unpack len type]
  (case type
    :A (string/format "%d.%d.%d.%d" ;(unpack :u8 :u8 :u8 :u8))
    :AAAA (string/format "%x:%x:%x:%x:%x:%x:%x:%x" ;(unpack :u16 :u16 :u16 :u16 :u16 :u16 :u16 :u16))
    :MX (unpack :u16 :name)
    :NS (unpack :name)
    :PTR (unpack :name)
    :TXT (let [[len] (unpack :u8) [txt] (unpack len)] txt)
   ))

(defn- decode-question [unpack]
  (def [name type class] (unpack :name :u16 :u16))
  {:name name :type (qtype type)})

(defn- decode-answer [unpack]
  (def [name type class ttl len] (unpack :name :u16 :u16 :u32 :u16))
  (def data (decode-data unpack len (qtype type)))
  {:name name :type (qtype type) :ttl ttl :data data})

(defn- decode-list [unpack decoder count]
  (def vs @[])
  (repeat count (array/push vs (decoder unpack)))
  vs)

(defn- dns-decode [buf]
  (def unpack (unpacker buf))
  (def [id flags nquestions nanswers] (unpack :u16 :u16 :u16 :u16 :u16 :u16))
  (def questions (decode-list unpack decode-question nquestions))
  (def answers (decode-list unpack decode-answer nanswers))
  {:id id :flags flags :questions questions :answers answers})

# :resolve method implementation; sends a DNS query and yields until the
# response is received.

(defn- fn-resolve [self name &opt type]
  (default type :A)
  (update self :id inc)
  # Send request to DNS server
  (def query-pkt {
            :id (self :id)
            :questions [ { :name name :type type } ]
            :answers []
          })
  (net/write (self :sock) (dns-encode query-pkt))
  # Store request and yield. The fiber will be resumed when an answer is received.
  (def req @{
     :id (self :id)
     :time (os/time)
     :fiber (fiber/current)
  })
  (put (self :requests) (self :id) req)
  (yield))

(defn- fn-stop [self]
  (net/close (self :sock)))

# Worker fiber reads responses and resumes request fibers

(defn- resolve_worker [resolver]
  (if-let [data (net/read (resolver :sock) 512)]
    (let [rsp (dns-decode data)
          req (get (resolver :requests) (rsp :id))]
    (if req (do
      (def result (map (fn [ans] (ans :data)) (rsp :answers)))
      (ev/go (req :fiber) result)
      (put (resolver :requests) (rsp :id) nil)))
    (resolve_worker resolver))))

# Create new resolver instance

(defn new [server]
  (def resolver @{
     # methods
     :resolve fn-resolve
     :stop fn-stop
     # data
     :sock (net/connect server "53" :datagram)
     :requests @{}
     :id 0
  })
  (ev/call resolve_worker resolver)
  resolver)
  

