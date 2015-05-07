#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <nfc/nfc.h>
#include <v8.h>
#include <node.h>
#include <node_buffer.h>
#include "mifare.h"

using namespace v8;
using namespace node;


static const nfc_modulation nmMifare = {
  NMT_ISO14443A,
  NBR_106,
};
static uint8_t keys[] = {
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7,
  0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5,
  0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5,
  0x4d, 0x3a, 0x99, 0xc3, 0x51, 0xdd,
  0x1a, 0x98, 0x2c, 0x7e, 0x45, 0x9a,
  0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xab, 0xcd, 0xef, 0x12, 0x34, 0x56
};
static size_t num_keys = sizeof(keys) / 6;

static nfc_device *dev;
static nfc_context *cont;
static bool keep_running = 0;

namespace {

    void NFCRead(uv_work_t* req);
    void AfterNFCRead(uv_work_t* req);

    struct NFC: ObjectWrap {
        static Handle<Value> New(const Arguments& args);
        static Handle<Value> Start(const Arguments& args);
        static Handle<Value> Stop(const Arguments& args);
    };

    Handle<Value> NFC::New(const Arguments& args) {
        HandleScope scope;
        assert(args.IsConstructCall());
        NFC* self = new NFC();
        self->Wrap(args.This());
        return scope.Close(args.This());
    }

    struct Baton {
        nfc_device *pnd;
        nfc_target nt;
        nfc_context *context;
        Persistent<Function> callback;
        int error;
        bool got_data;
    };

    Handle<Value> NFC::Start(const Arguments& args) {
        HandleScope scope;
        nfc_context *context;
        nfc_init(&context);
        if (context == NULL) return ThrowException(Exception::Error(String::New("unable to init libfnc (malloc).")));

        nfc_device *pnd;

        pnd = nfc_open(context, NULL);

        if (pnd == NULL) {
            nfc_exit(context);
            return ThrowException(Exception::Error(String::New("unable open NFC device")));
        }

        dev = pnd;
        cont = context;

        char result[BUFSIZ];
        if (nfc_initiator_init(pnd) < 0) {
            snprintf(result, sizeof result, "nfc_initiator_init: %s", nfc_strerror(pnd));
            nfc_close(pnd);
            nfc_exit(context);
            return ThrowException(Exception::Error(String::New(result)));
        }

        Baton* baton = new Baton();
        baton->context = context;
        baton->pnd = pnd;

        Handle<Function> cb = Handle<Function>::Cast(args.This());
        baton->callback = Persistent<Function>::New(cb);

        uv_work_t *req = new uv_work_t();
        req->data = baton;

        keep_running = 1;
        
        uv_queue_work(uv_default_loop(), req, NFCRead, (uv_after_work_cb)AfterNFCRead);
        //        Loop(baton);
        Local<Object> object = Object::New();
        //        object->Set(NODE_PSYMBOL("deviceID"), String::New(nfc_device_get_connstring(baton->pnd)));
        //object->Set(NODE_PSYMBOL("name"), String::New(nfc_device_get_name(baton->pnd)));

        

        return scope.Close(object);
    }

    Handle<Value> NFC::Stop(const Arguments& args) {
        HandleScope scope;
        keep_running = 0;
        if(dev) {
          nfc_close(dev);
        }
        if(cont) {
          nfc_exit(cont);
        }

        Local<Object> object = Object::New();

        return scope.Close(object);
    }

    void Loop(Baton *baton) {
      if(!keep_running) {
        return;
      }
        HandleScope scope;

        uv_work_t *req = new uv_work_t();
        req->data = baton;
        uv_queue_work(uv_default_loop(), req, NFCRead, (uv_after_work_cb)AfterNFCRead);
    }

    void NFCRead(uv_work_t* req) {

      Baton* baton = static_cast<Baton*>(req->data);

      baton->got_data = false;


      baton->error = nfc_initiator_list_passive_targets(baton->pnd, nmMifare, &(baton->nt), 1);


      if(baton->error < 0) {
        keep_running = 0;
        nfc_close(baton->pnd);
        nfc_exit(cont);
        dev = NULL;
        cont = NULL;
        return;
      }

      if(baton->error == 0) {
        return;
      }

      baton->got_data = true;
    }

#define MAX_DEVICE_COUNT 16
#define MAX_FRAME_LENGTH 264

  void AfterNFCRead(uv_work_t* req) {
    HandleScope scope;
    unsigned long cc, n;
    char *bp;
    const char *sp;
    Baton* baton = static_cast<Baton*>(req->data);
    Handle<Value> argv[2];

    if(!(baton->got_data)) {
      delete req;
      Loop(baton);
      return;
    }

    if(baton->error < 0) {
      char errmsg[BUFSIZ];

      snprintf(errmsg, sizeof errmsg, "nfc_initiator_select_passive_target: %s", nfc_strerror(baton->pnd));
      
      argv[0] = String::New("error");
      argv[1] = String::New(errmsg);
      
      MakeCallback(baton->callback, "emit", 2, argv);
      
      delete req;
      return;
    }    
      
    Local<Object> object = Object::New();
    
    cc = baton->nt.nti.nai.szUidLen;
    if(cc > sizeof baton->nt.nti.nai.abtUid) {
      cc = sizeof baton->nt.nti.nai.abtUid;
    }
    char uid[3 * sizeof baton->nt.nti.nai.abtUid];
    bzero(uid, sizeof uid);
    
    for(n = 0, bp = uid, sp = ""; n < cc; n++, bp += strlen(bp), sp = ":") {
      snprintf(bp, sizeof uid - (bp - uid), "%s%02x", sp, baton->nt.nti.nai.abtUid[n]);
    }
    object->Set(NODE_PSYMBOL("uid"), String::New(uid));
    
    
    argv[0] = String::New("read");
    argv[1] = object;
    MakeCallback(baton->callback, "emit", sizeof argv / sizeof argv[0], argv);

    delete req;
  
    Loop(baton);
  }
  
  


    Handle<Value> Scan(const Arguments& args) {
        HandleScope       scope;

        nfc_context *context;
        nfc_init(&context);
        if (context == NULL) return ThrowException(Exception::Error(String::New("unable to init libfnc (malloc).")));

        Local<Object> object = Object::New();

        nfc_connstring connstrings[MAX_DEVICE_COUNT];
        size_t i, n = nfc_list_devices(context, connstrings, MAX_DEVICE_COUNT);
        for (i = 0; i < n; i++) {
            Local<Object> entry = Object::New();
            nfc_device *pnd = nfc_open(context, connstrings[i]);
            if (pnd == NULL) continue;

            entry->Set(NODE_PSYMBOL("name"), String::New(nfc_device_get_name(pnd)));

            char *info;
            if (nfc_device_get_information_about(pnd, &info) >= 0) {
                entry->Set(NODE_PSYMBOL("info"), String::New(info));
                nfc_free(info);
            } else {
                entry->Set(NODE_PSYMBOL("info"), String::New(""));
            }
            object->Set(NODE_PSYMBOL(nfc_device_get_connstring(pnd)), entry);

            nfc_close(pnd);
        }

        nfc_exit(context);

        return scope.Close(object);
    }

    Handle<Value> Version(const Arguments& args) {
        HandleScope       scope;

        nfc_context *context;
        nfc_init(&context);
        if (context == NULL) return ThrowException(Exception::Error(String::New("unable to init libfnc (malloc).")));

        Local<Object> object = Object::New();
        object->Set(NODE_PSYMBOL("name"), String::New("libnfc"));
        object->Set(NODE_PSYMBOL("version"), String::New(nfc_version()));

        nfc_exit(context);

        return scope.Close(object);
    }

    extern "C" void init(Handle<Object> target) {
        HandleScope scope;

        Local<FunctionTemplate> t = FunctionTemplate::New(NFC::New);
        t->InstanceTemplate()->SetInternalFieldCount(1);
        t->SetClassName(String::New("NFC"));
        NODE_SET_PROTOTYPE_METHOD(t, "start", NFC::Start);
        NODE_SET_PROTOTYPE_METHOD(t, "stop", NFC::Stop);
        target->Set(String::NewSymbol("NFC"), t->GetFunction());

        target->Set(String::NewSymbol("scan"), FunctionTemplate::New(Scan)->GetFunction());
        target->Set(String::NewSymbol("version"), FunctionTemplate::New(Version)->GetFunction());
    }

}

NODE_MODULE(nfc, init)
