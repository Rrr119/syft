extern const char *syft_04_identity(void);
int main(void) {
    return syft_04_identity()[0] == 's' ? 0 : 1;
}
