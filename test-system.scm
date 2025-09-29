(use-modules
  (guix)
  (guix build-system zig)
  (gnu)
  (gnu system privilege)
  (gnu packages zig)
  (gnu packages text-editors)
  (gnu packages linux))

(define sudo-ku
 (package
  (name "sudo-ku")
  (version "0")
  (source (local-file (current-source-directory)
                      #:recursive? #t
                      #:select? (lambda (f _)
                                  (not (or (string-contains f ".zig-cache")
                                           (string-contains f ".git")
                                           (string-contains f "zig-out"))))))
  (build-system zig-build-system)
  (arguments (list
             #:tests? #f
             #:phases
              #~(modify-phases %standard-phases
                 (delete 'validate-runpath)) ; validation fails, but the executable works anyways
             #:zig-build-flags
             #~(list "--search-prefix" #$linux-pam)
             #:zig zig-0.15))
  (synopsis "")
  (description "")
  (inputs (list linux-pam))
  (home-page #f)
  (license #f)))

(operating-system
 (host-name "test-system")
 (issue "Welcome to the sudo-ku test system\nuser: tester\npassword: tester\n")
 (bootloader (bootloader-configuration  ;; this will be ignored...
               (bootloader grub-efi-bootloader)
               (targets '("/boot/efi"))))
 (file-systems '())
 (users (cons (user-account
               (name "tester")
               (password (crypt "tester" "$6$abc"))
               (group "users")
               (supplementary-groups '("wheel")))
              %base-user-accounts))
 (packages (cons helix %base-packages))
 (privileged-programs (cons (privileged-program
                             (program (file-append sudo-ku "/bin/sudo-ku"))
                             (setuid? #t))
                            %default-privileged-programs))
 (pam-services (cons (pam-service
                       (name "sudo-ku")
                       (auth (list (pam-entry
                               (control "required")
                               (module "pam_unix.so")))))
                     (base-pam-services)))
 (services (cons
   (simple-service 'sudo-kuers-file etc-service-type
      `(("sudo-kuers" ,(file-append sudo-ku "/etc/sudo-kuers"))))
   %base-services)))
